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

## Stage-1 model

The stage-1 model is served by llama.cpp's `llama-server` (`~/tools/llama.cpp`,
model GGUFs in `~/models/pps/`); `scripts/run-llm.sh` is the exact command the
`llama-guard` user unit runs.

Current model: **Qwen3-4B-Instruct-2507, Q4_K_M** (2.5 GB file). Flags that
matter, and why (measured 2026-10-16 on the 24-core EPYC, CPU only):

| Flag | Why |
|---|---|
| `--threads 24` | physical cores; 48 threads is ~2x slower, 12 is 1.5x slower |
| `-c 8192 -np 2` | two 4096-token slots; a judgment is at most ~2.5k tokens (6000-char text + policy) |
| `-fa on -ctk q8_0 -ctv q8_0` | 8-bit KV cache: no measurable speed or accuracy cost on CPU, smaller RSS |
| `--cache-ram 1024` | the server-wide prompt cache defaults to 8 GiB and fills up over a day; it is what took the server from ~5 GB to ~14 GB RSS. 1 GiB keeps the useful part (shared system prompt + a few policies) |

With these the server starts at ~4.8 GB RSS and stays near 5 GB. `scripts/eval.py`
passes 32/32 at p50 1.7 s per judgment (2.3 s the day before with four
8192-token slots and the default cache; box load differed, so treat the
speedup as "no slower").

### Qwen3.5-4B, evaluated and rejected (2026-10-16)

Qwen3.5-4B (Q4_K_M, thinking disabled via
`--chat-template-kwargs '{"enable_thinking":false}'`; `--reasoning-budget 0`
does not work for its template) was run side by side on 1,105 historical
judgments and the labeled eval:

- **Memory:** no gain (4.1 GB vs 4.8 GB at start; the prompt cache dominated both).
- **Speed:** ~2x slower per judgment on CPU (p50 4.2 s vs 2.3 s single stream;
  5.0 s vs 2.3 s per row under replay). Its hybrid DeltaNet layers have slow CPU
  kernels; threads and flags do not help. Alfred's voice path gives a guest's
  act tool 6 s to wait for a speech verdict, so this sits at the budget.
- **Accuracy:** a wash. Better on Alfred call cards (it follows the "to-dos that
  mention calling/deleting are allowed" rule, where Qwen3-4B still produces
  ~1% "destructive" false denies); worse on Slack guests (3 new false denies on
  in-scope game-feature requests out of 127, incl. "rename the app to Jeutopia");
  identical on factory customers; neither model missed a genuine attack. Labeled
  eval 31/32 vs 32/32.

Re-evaluate when a build with faster DeltaNet CPU kernels or a stronger
small dense instruct model appears. Replay tooling: `/tmp/pps-replay/` at the
time (replay.py rebuilds each caller's policy from the live sources; analyze.py
compares two runs).

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
