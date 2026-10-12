# pps — Prompt Protection Service

Local, sandboxed LLM judge that screens messages headed for AI coding agents
(slackcc → T3 Code today; voice later). It classifies, never executes: even a
fully jailbroken judge can only return `{"verdict": ...}` JSON.

## Architecture

```
caller (slackcc / voice shim)
   │  POST /v1/judge {sender, policy, text, context}
   ▼
pps (this service, :8642, stdlib python)
   ├─ stage 0: fast injection classifier (optional, ms, transformers)
   └─ stage 1: small guard LLM ── llama-server (:8641, CPU) applies the
               per-sender policy → {"verdict": allow|deny, category, reason}
```

- **pps is a screen, not the wall.** Deterministic enforcement lives elsewhere:
  per-sender T3 `runtimeMode` (slackcc `config/senders.json`), the PreToolUse
  guard hook (`hooks/claude_guard.py`, installed in each bridged project's
  `.claude/settings.json`), and outbound secret scrubbing in slackcc.
- Verdict `error` (LLM down, unparseable) is returned as-is; the caller decides
  fail-open vs fail-closed. slackcc fails CLOSED for guests.
- Every judgment is appended to `.state/audit.jsonl` (includes message text —
  local only) for false-positive tuning.

## Run

```bash
scripts/run.sh                 # uses ~/models/pps/venv if present (stage 0), else python3
python3 scripts/eval.py        # labeled smoke-eval against the live service
```

Env (see `src/pps/config.py`): `PPS_PORT` (8642), `PPS_LLM_URL`
(http://127.0.0.1:8641), `PPS_STAGE0_DIR` (classifier model dir; empty = skip),
`PPS_STAGE0_THRESHOLD` (0.9), `PPS_MAX_TEXT_CHARS` (6000).

Stage 0 is advisory only: it never denies. Every message goes to the stage-1
LLM, which sees the sender's policy and makes the call; a classifier score >=
`PPS_STAGE0_THRESHOLD` is recorded in the verdict reason (`stage:
"classifier+llm"` in the audit log). It used to auto-deny at >= 0.98, but on
real guest traffic (2026-10) it scored ordinary imperative feature requests
("no need for the continue button, just move to the next turn") at 0.96-1.00,
the same band as real payloads -- 10 of 18 Slack false positives. The LLM
alone denies the blatant payloads it used to catch (`scripts/eval.py`).

The guest policy should say what the project *is*, not just its name. With
only a name, the 4B judge rules in-domain requests out of scope (a board
game's "Mazel cards" and "fabric tokens"); slackcc appends each channel's
`description` for this.

```bash
python3 -m unittest discover -s tests -v   # unit tests for the judge routing (no live services needed)
```

The stage-1 model is served by llama.cpp's `llama-server` (`~/tools/llama.cpp`,
model GGUFs in `~/models/pps/`) — see the exact command in `/tmp/llama-guard.log`
startup or the systemd notes below.

## Secret scanner (shared library)

`src/pps/secrets.py` is the **one secret scanner on this machine**. Other
projects import it instead of keeping their own patterns, so a new token shape
is added once and protects everything:

| User | What it does with it |
|---|---|
| slackcc (`slackcc/outbound.py`) | `redact()` on every outbound Slack message, with its own env secrets as `known` |
| software factory gate (planned) | `find()` over candidate commits/blobs, with the client's env values as `known` |

It is stdlib-only and does no I/O; importing `pps.secrets` does not import the
service (`pps.server`, `pps.judge`) or any dependency.

```bash
# install a copy, pinned to a release tag (not a live checkout that agents switch branches in)
pip install "pps @ git+https://github.com/DanielGGordon/Prompt-Protection-Service.git@secrets-v0.1.0"
```

```python
from pps.secrets import find, redact

known = {"DB_PASSWORD": db_password}            # {NAME: value}; optional

for f in find(blob, known):                     # str or bytes -> list[Finding]
    print(f.label, f.var, f.line, f.start, f.end)   # never the value

clean, labels = redact(text, known)             # -> (text with secrets replaced, labels)
```

- `find(data, known=None, *, allow=(), max_input=, max_seconds=, min_known_len=, ignore_placeholders=False)`
  returns `Finding(label, start, end, line, var, form)` in position order.
  `bytes` input gives byte offsets; `str` gives character offsets.
- `redact(text, known=None, ...)` returns `(clean, labels)` with slackcc's
  conventions: shapes become `[redacted:<label>]`, known values
  `[redacted:<VAR>]` (label `own-secret:<VAR>`), and `api_key = "..."` keeps the
  key and separator and becomes `[redacted]`. Bytes in, bytes out.
- **Known values** match exactly and in the encoded forms a leak usually takes:
  hex (either case), base64 / url-safe base64 at any alignment (so inside a
  larger blob too), and percent-encoding. Values under 8 bytes (and empty ones)
  are ignored. `allow=` lists public values (e.g. a documented dummy credential)
  that must not be reported.
- **Shapes**: private keys, Slack tokens and webhooks, AWS key ids, GitHub
  (`ghp_`/`github_pat_`), GitLab, JWT, Anthropic (`sk-ant-`), OpenAI
  (`sk-`/`sk-proj-`), Clerk/Stripe (`sk_live_`, `sk_test_`, `pk_live_`,
  `rk_live_`), Google API keys, npm tokens; plus contextual rules for
  `api_key = ...` assignments, passwords in database URLs and high-entropy
  quoted secrets. `pps.secrets.PATTERN_LABELS` lists them in priority order;
  an earlier rule claims its text first (Anthropic before the generic `sk-`).
  Pass `ignore_placeholders=True` when scanning source code so values like
  `change-me` or `${PASSWORD}` are not reported.

**The never-carry-values rule.** A `Finding` has no field for the matched text,
its `repr`/`str` never show any of it, and the module never logs it. Callers
must follow suit: print the label, the variable name and a position -- never
the value. (To show context, re-read the surrounding text yourself and mask the
span.)

**Bounded work.** Input is capped at `DEFAULT_MAX_INPUT` (1 MiB; chars for `str`,
bytes for `bytes`) and a call has a `DEFAULT_MAX_SECONDS` (10 s) budget; pass
`max_input=` / `max_seconds=` for different limits. Over the size cap, `find`
reports an `input-truncated` finding for the unscanned tail and `redact` replaces
that tail with `[redacted:input-truncated]`; on timeout `find` returns a single
`scan-timeout` finding and `redact` returns `[redacted:scan-timeout]` instead of
the text. The time check runs between rules (a regex cannot be interrupted), so
the patterns are written to be linear-time; `tests/test_secrets.py` runs
adversarial 1 MiB inputs to keep them that way.

Adding a shape: add a `_r(...)` line to `_RULES` in `secrets.py` (mind the
order), a case to `PatternTests.SHAPES` and, if it is contextual, a test of what
it must not match.

## Guard hook

`hooks/claude_guard.py` is a PreToolUse hook blocking mass deletion, secret
file access (.env/.ssh/.aws/.t3/…), env dumps, curl|sh, and edits to guard
config. Installed in: `~/cursor/sofer-ai` and `~/gphotos-to-constant-contact`
(`.claude/settings.json`). It applies to ALL sessions in those projects;
`CLAUDE_GUARD_OFF=1` bypasses it for your own shell work.
