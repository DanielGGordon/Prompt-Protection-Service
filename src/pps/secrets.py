"""The one secret scanner on this machine.

Shared by slackcc (outbound Slack scrubbing) and the software factory's gate
(leak scan of candidate code). Stdlib only, no I/O, no global state: import it
without pulling in anything else from pps.

    from pps.secrets import find, redact

    findings = find(blob, known={"DB_PASSWORD": value})   # list[Finding]
    clean, labels = redact(text, known={"SLACK_BOT_TOKEN": value})

Two layers, in this priority order:

1. *Known values* -- exact values the caller holds (``{NAME: value}``), plus the
   encoded forms a leaked copy usually takes: hex (lower/upper), base64 and
   url-safe base64 at every alignment (so a value embedded inside a larger
   base64 blob is still caught), and percent-encoding. Zero false negatives
   for the credentials the caller knows about.
2. *Shapes* -- the ``PATTERNS`` table: well-known token formats (private keys,
   Slack, AWS, GitHub, GitLab, Anthropic, OpenAI, Clerk/Stripe, Google, npm,
   JWT) plus contextual rules (``api_key = "..."`` assignments, passwords in
   database URLs, high-entropy quoted secrets).

**The never-carry-values rule.** A ``Finding`` names the rule (and the variable
name for a known value) and where it matched. It never holds, and its
``repr``/``str`` never show, the matched text -- not even partially -- and this
module never logs matched text. Callers keep to the same rule: print the label,
the variable name and a position, never the value.

**Bounded work.** Each call is capped (see ``DEFAULT_MAX_INPUT`` and
``DEFAULT_MAX_SECONDS``; pass ``max_input=`` / ``max_seconds=`` for different
caps). The scan is fail-closed, never silently partial: input past the cap is
reported as an ``input-truncated`` finding (``redact`` drops the unscanned tail
and says so), and running out of time is a ``scan-timeout`` finding (``redact``
then returns a placeholder instead of the text). The time cap is checked
between rules, not inside a regex, so it is a backstop; the patterns themselves
are written to run in linear time (see the tests).

``bytes`` input is scanned byte-for-byte (positions are byte offsets, no
decoding errors); ``str`` input is scanned as text (positions are characters).
"""

from __future__ import annotations

import base64
import logging
import math
import re
import time
import urllib.parse
from bisect import bisect_left
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "DEFAULT_MAX_INPUT",
    "DEFAULT_MAX_SECONDS",
    "KNOWN_LABEL",
    "MIN_KNOWN_LEN",
    "PATTERN_LABELS",
    "Finding",
    "find",
    "redact",
]

log = logging.getLogger(__name__)

#: Largest input scanned per call, in ``len()`` units (chars for ``str``, bytes
#: for ``bytes``). Slack messages are tens of KB; the gate passes its own
#: per-file cap explicitly.
DEFAULT_MAX_INPUT = 1 << 20
#: Wall-clock budget per call, checked between rules.
DEFAULT_MAX_SECONDS = 10.0
#: Known values (and each encoded form) shorter than this are ignored: matching
#: a 3-character "secret" would redact ordinary words.
MIN_KNOWN_LEN = 8
#: Label of a hit on a caller-supplied known value; ``Finding.var`` names it.
KNOWN_LABEL = "own-secret"

_TRUNCATED = "input-truncated"
_TIMEOUT = "scan-timeout"
# When redact() truncates, it also drops this many already-scanned chars before
# the cut, so a token straddling the cut cannot leak a prefix.
_TAIL_GUARD = 256


@dataclass(frozen=True, slots=True)
class Finding:
    """One hit. Deliberately has no field for the matched text."""

    label: str            # rule name, e.g. "anthropic-key"; KNOWN_LABEL for a known value
    start: int            # offset of the secret (chars for str input, bytes for bytes input)
    end: int              # offset just past it
    line: int             # 1-based line of ``start``
    var: str | None = None   # variable name, for known-value hits
    form: str | None = None  # known-value hits: "exact", "hex", "base64", "urlencoded"

    def __str__(self) -> str:
        who = f"{self.label}:{self.var}" if self.var else self.label
        return f"{who} at line {self.line}"


# ----------------------------------------------------------------- the rules


def _entropy(v: str) -> float:
    if not v:
        return 0.0
    counts: dict[str, int] = {}
    for c in v:
        counts[c] = counts.get(c, 0) + 1
    n = len(v)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


_PLACEHOLDER = re.compile(
    r"(?i)example|placeholder|change-?me|changeme|xxxx|dummy|fake|redacted|your[_\-]|sample|\$\{|process\.env|<|>")
_DOTTED_IDENT = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")


def _plausible(v: str) -> bool:
    """False for values that are obviously not credentials: placeholders
    ("change-me", "${VAR}", "<your-key>"), dotted identifiers, paths and URLs."""
    return not (_PLACEHOLDER.search(v) or _DOTTED_IDENT.match(v) or v.startswith(("/", "http")) or "://" in v)


def _looks_secret(min_entropy: float) -> Callable[[str], bool]:
    def check(v: str) -> bool:
        if not _plausible(v):
            return False
        if not re.search(r"[0-9]", v) or not re.search(r"[A-Za-z]", v):
            return False
        return _entropy(v) >= min_entropy
    return check


@dataclass(frozen=True, slots=True)
class _Rule:
    label: str
    rx: re.Pattern[str]
    group: int = 0                       # the part that is redacted / reported
    marker: str | None = None            # replacement text; None -> "[redacted:<label>]"
    check: Callable[[str], bool] | None = None   # extra filter on the group text
    per_match: bool = False              # redact() lists the label once per match
    placeholder_filter: bool = False     # skipped for obvious placeholders when ignore_placeholders=True


_A = re.ASCII
_AI = re.ASCII | re.IGNORECASE
_SECRET_WORD = (r"(?:secret|token|passw(?:or)?d|pwd|api[_\-]?key|apikey|private[_\-]?key|"
                r"access[_\-]?key|auth[_\-]?key|credential)")
_PEM_NAME = r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?"


def _r(label: str, pattern: str, flags: int = _A, **kw) -> _Rule:
    return _Rule(label, re.compile(pattern, flags), **kw)


# Order matters: an earlier rule claims its text first and a later rule cannot
# match inside it. In particular anthropic-key precedes the generic sk- rule
# (else sk-ant- keys would be mislabelled openai-key), and the contextual
# rules come last so a recognised token keeps its specific label.
_RULES: tuple[_Rule, ...] = (
    _r("private-key", rf"-----BEGIN {_PEM_NAME}-----[\s\S]*?(?:-----END {_PEM_NAME}-----|\Z)"),
    _r("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    _r("slack-app-token", r"\bxapp-[A-Za-z0-9-]{10,}"),
    _r("slack-webhook", r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    _r("aws-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _r("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    _r("github-pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    _r("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    # Two accepted shapes: the strict 3-segment JWT, and any eyJ.eyJ.* pair with
    # shorter segments. The lookbehind (not \b) keeps the scan linear: a start
    # can only be at the beginning of a run of token characters.
    _r("jwt", r"(?<![A-Za-z0-9_-])eyJ(?:[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"
              r"|[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    _r("anthropic-key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    _r("openai-key", r"(?:sk-proj-|\bsk-)[A-Za-z0-9_-]{20,}"),
    _r("clerk-or-stripe-secret-key", r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}"),
    _r("live-publishable-key", r"\bpk_live_[A-Za-z0-9]{20,}"),
    _r("stripe-restricted-key", r"\brk_live_[A-Za-z0-9]{20,}"),
    _r("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}"),
    _r("npm-token", r"\bnpm_[A-Za-z0-9]{36}"),
    # Contextual: keeps the key name, separator and quote; redacts the value as
    # a bare "[redacted]" (slackcc's historical output) and lists the label per match.
    _r("keyish-assignment",
       r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\b"
       r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+.]{16,})",
       _AI, group=1, marker="[redacted]", per_match=True, placeholder_filter=True),
    _r("database-url-with-password",
       r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:/\s@\"']*:([^@\s/\"']{8,})@",
       group=1, check=_looks_secret(3.0)),
    _r("high-entropy-assignment",
       rf"{_SECRET_WORD}[A-Za-z0-9_.\-]{{0,64}}[\"']?\s{{0,16}}[:=]\s{{0,16}}[\"'`]([^\"'`\s]{{16,}})[\"'`]",
       _AI, group=1, check=_looks_secret(3.5)),
    _r("high-entropy-assignment",
       rf"^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]{{0,64}}{_SECRET_WORD}[A-Za-z0-9_]{{0,64}}[ \t]*=[ \t]*"
       rf"([^\s\"'`#]{{16,}})[ \t\r]*$",
       _AI | re.MULTILINE, group=1, check=_looks_secret(3.5)),
)

#: Labels of the shape rules, in priority order (for docs and tests).
PATTERN_LABELS: tuple[str, ...] = tuple(dict.fromkeys(r.label for r in _RULES))


# ------------------------------------------------------------- known values


def _b64_cores(v: bytes) -> set[bytes]:
    """Base64 (std and url-safe) of ``v`` at every alignment, minus the edge
    characters that depend on the neighbouring bytes -- what remains appears
    verbatim wherever ``v`` is embedded in a larger base64 string."""
    cores: set[bytes] = set()
    n = len(v)
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        for pad in range(3):
            e = enc(b"\0" * pad + v).rstrip(b"=")
            skip = (pad * 8 + 5) // 6
            tail = 0 if (pad + n) % 3 == 0 else 1
            core = e[skip:len(e) - tail]
            if len(core) >= 8:
                cores.add(core)
    return cores


def _variants(v: bytes, min_len: int) -> list[tuple[bytes, str]]:
    out: dict[bytes, str] = {v: "exact"}
    out.setdefault(v.hex().encode(), "hex")
    out.setdefault(v.hex().upper().encode(), "hex")
    for c in sorted(_b64_cores(v)):
        out.setdefault(c, "base64")
    out.setdefault(urllib.parse.quote(v, safe="").encode(), "urlencoded")
    return [(x, form) for x, form in out.items() if len(x) >= min_len]


def _domain(value: str | bytes | bytearray, bytes_mode: bool) -> str | None:
    """Value as the text the engine scans: latin-1 view for bytes input, the
    str itself for str input. None if a bytes value is not valid UTF-8 text."""
    if bytes_mode:
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return raw.decode("latin-1")
    if isinstance(value, str):
        return value
    try:
        return bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _needles(known: Mapping[str, str | bytes] | None, bytes_mode: bool, min_len: int,
             allow: frozenset[str]) -> list[tuple[str, str, str]]:
    """[(needle, var, form)], longest first so a whole value is claimed before
    any shorter overlap."""
    seen: dict[str, tuple[str, str]] = {}
    for name, value in (known or {}).items():
        if not value:
            continue
        raw = (value.encode("utf-8") if isinstance(value, str) else bytes(value)).strip()
        if len(raw) < min_len:
            continue
        exact = _domain(raw, bytes_mode)
        if exact is not None and exact in allow:
            continue
        for x, form in _variants(raw, min_len):
            text = _domain(x, bytes_mode)
            if text is not None:
                seen.setdefault(text, (name, form))
    items = [(t, name, form) for t, (name, form) in seen.items()]
    items.sort(key=lambda t: -len(t[0]))
    return items


# --------------------------------------------------------------------- scan

_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_")


def _extend_base64(text: str, j: int) -> int:
    """A base64 needle omits the last character (it depends on what follows)
    and the ``=`` padding; take them into the span so a redaction leaves no stub."""
    if j < len(text) and text[j] in _B64_CHARS:
        j += 1
    for _ in range(2):
        if j < len(text) and text[j] == "=":
            j += 1
    return j


class _Spans:
    """Accepted, non-overlapping [start, end) spans."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def free(self, s: int, e: int) -> bool:
        i = bisect_left(self.starts, s)
        if i < len(self.starts) and self.starts[i] < e:
            return False
        if i > 0 and self.ends[i - 1] > s:
            return False
        return True

    def add(self, s: int, e: int) -> None:
        i = bisect_left(self.starts, s)
        self.starts.insert(i, s)
        self.ends.insert(i, e)


@dataclass(slots=True)
class _Hit:
    start: int
    end: int
    rule: _Rule | None       # None -> known value
    var: str | None = None
    form: str | None = None


@dataclass(slots=True)
class _Scan:
    text: str
    is_bytes: bool
    hits: list[_Hit]
    truncated_at: int | None  # input was longer than the cap; scanned text[:truncated_at]
    total_len: int
    timed_out: bool


def _run(data: str | bytes | bytearray | memoryview, known, allow, max_input: int,
         max_seconds: float, min_known_len: int, ignore_placeholders: bool) -> _Scan:
    deadline = time.monotonic() + max_seconds
    if isinstance(data, str):
        text, is_bytes = data, False
    elif isinstance(data, (bytes, bytearray, memoryview)):
        text, is_bytes = bytes(data).decode("latin-1"), True
    else:
        raise TypeError(f"expected str or bytes, got {type(data).__name__}")
    total = len(text)
    truncated_at = None
    if total > max_input:
        truncated_at = max_input
        text = text[:max_input]
        log.warning("secret scan input over cap (%d > %d); unscanned tail reported", total, max_input)

    allowed = frozenset(a for a in (_domain(x, is_bytes) for x in allow) if a is not None)
    spans = _Spans()
    hits: list[_Hit] = []

    def timed_out() -> bool:
        if time.monotonic() > deadline:
            log.warning("secret scan exceeded %.1fs budget on %d chars", max_seconds, len(text))
            return True
        return False

    for needle, var, form in _needles(known, is_bytes, min_known_len, allowed):
        if timed_out():
            return _Scan(text, is_bytes, hits, truncated_at, total, True)
        i = text.find(needle)
        while i != -1:
            j = i + len(needle)
            if form == "base64":
                j = _extend_base64(text, j)
            if spans.free(i, j):
                spans.add(i, j)
                hits.append(_Hit(i, j, None, var, form))
            i = text.find(needle, i + len(needle))

    for rule in _RULES:
        if timed_out():
            return _Scan(text, is_bytes, hits, truncated_at, total, True)
        for m in rule.rx.finditer(text):
            s, e = m.span(rule.group)
            if e <= s or not spans.free(s, e):
                continue
            value = m.group(rule.group)
            if value in allowed or (rule.check is not None and not rule.check(value)):
                continue
            if ignore_placeholders and rule.placeholder_filter and not _plausible(value):
                continue
            spans.add(s, e)
            hits.append(_Hit(s, e, rule))
    hits.sort(key=lambda h: h.start)
    return _Scan(text, is_bytes, hits, truncated_at, total, False)


# ---------------------------------------------------------------- public API


def find(data: str | bytes, known: Mapping[str, str | bytes] | None = None, *,
         allow: Iterable[str | bytes] = (), max_input: int = DEFAULT_MAX_INPUT,
         max_seconds: float = DEFAULT_MAX_SECONDS, min_known_len: int = MIN_KNOWN_LEN,
         ignore_placeholders: bool = False) -> list[Finding]:
    """Everything in ``data`` that looks like a secret, in position order.

    ``known`` maps variable names to secret values; exact and encoded copies
    are reported with ``label == KNOWN_LABEL`` and ``var`` set to the name.
    ``allow`` lists public values that must not be reported (e.g. a documented
    dummy credential). ``ignore_placeholders=True`` additionally lets the
    ``api_key = "..."`` rule skip obvious placeholders (``change-me``,
    ``${VAR}``, paths, URLs) -- for scanning source code, where those are
    everywhere; the default (off) redacts them, which is right for chat.
    Findings never contain the matched text.

    Oversize input yields a final ``input-truncated`` finding spanning the
    unscanned tail; running out of time yields a single ``scan-timeout``
    finding (results so far are discarded: the scan is not trustworthy).
    """
    scan = _run(data, known, allow, max_input, max_seconds, min_known_len, ignore_placeholders)
    if scan.timed_out:
        return [Finding(_TIMEOUT, 0, scan.total_len, 1)]
    out: list[Finding] = []
    line, pos = 1, 0
    for h in scan.hits:  # sorted by start, so one pass counts the lines
        line += scan.text.count("\n", pos, h.start)
        pos = h.start
        if h.rule is None:
            out.append(Finding(KNOWN_LABEL, h.start, h.end, line, h.var, h.form))
        else:
            out.append(Finding(h.rule.label, h.start, h.end, line))
    if scan.truncated_at is not None:
        tail_line = line + scan.text.count("\n", pos, scan.truncated_at)
        out.append(Finding(_TRUNCATED, scan.truncated_at, scan.total_len, tail_line))
    return out


def redact(text: str | bytes, known: Mapping[str, str | bytes] | None = None, *,
           allow: Iterable[str | bytes] = (), max_input: int = DEFAULT_MAX_INPUT,
           max_seconds: float = DEFAULT_MAX_SECONDS,
           min_known_len: int = MIN_KNOWN_LEN,
           ignore_placeholders: bool = False) -> tuple[str | bytes, list[str]]:
    """Returns ``(clean_text, labels)``; the clean text has the same type as the input.

    Conventions (slackcc's, unchanged): a known value becomes
    ``[redacted:<VAR>]`` and adds ``own-secret:<VAR>`` once per variable; a
    shape becomes ``[redacted:<label>]`` and adds its label once per rule; an
    ``api_key = "..."``-style assignment keeps the key, separator and quote and
    becomes ``[redacted]``, adding ``keyish-assignment`` for every match.
    Known-variable labels come first (in ``known`` order), then rule labels in
    table order. Text with nothing to redact is returned as is.

    Fail-closed on the caps: past ``max_input`` the unscanned tail (and the last
    256 scanned characters before it) is replaced by ``[redacted:input-truncated]``;
    on timeout the whole text is replaced by ``[redacted:scan-timeout]``.
    """
    scan = _run(text, known, allow, max_input, max_seconds, min_known_len, ignore_placeholders)

    def out(s: str) -> str | bytes:
        return s.encode("latin-1") if scan.is_bytes else s

    if scan.timed_out:
        return out(f"[redacted:{_TIMEOUT}]"), [_TIMEOUT]

    cut = None if scan.truncated_at is None else max(0, scan.truncated_at - _TAIL_GUARD)
    pieces: list[str] = []
    pos = 0
    known_seen: set[str] = set()
    counts: dict[str, int] = {}       # rule label -> matches
    for h in scan.hits:
        if cut is not None and h.start >= cut:
            break
        pieces.append(scan.text[pos:h.start])
        if h.rule is None:
            pieces.append(f"[redacted:{h.var}]")
            known_seen.add(h.var)
        else:
            pieces.append(h.rule.marker or f"[redacted:{h.rule.label}]")
            counts[h.rule.label] = counts.get(h.rule.label, 0) + 1
        pos = h.end
    labels: list[str] = [f"{KNOWN_LABEL}:{v}" for v in (known or {}) if v in known_seen]
    for rule in _RULES:   # table order; a label shared by two rules is listed once
        n = counts.pop(rule.label, 0)
        if n:
            labels.extend([rule.label] * (n if rule.per_match else 1))
    if cut is not None:
        pieces.append(scan.text[pos:cut] if pos < cut else "")
        pieces.append(f"[redacted:{_TRUNCATED}]")
        labels.append(_TRUNCATED)
    elif not scan.hits:
        return text, []
    else:
        pieces.append(scan.text[pos:])
    return out("".join(pieces)), labels
