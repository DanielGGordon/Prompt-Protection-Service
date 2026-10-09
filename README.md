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

## Guard hook

`hooks/claude_guard.py` is a PreToolUse hook blocking mass deletion, secret
file access (.env/.ssh/.aws/.t3/…), env dumps, curl|sh, and edits to guard
config. Installed in: `~/cursor/sofer-ai` and `~/gphotos-to-constant-contact`
(`.claude/settings.json`). It applies to ALL sessions in those projects;
`CLAUDE_GUARD_OFF=1` bypasses it for your own shell work.
