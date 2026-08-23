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
`PPS_STAGE0_THRESHOLD` (0.9), `PPS_STAGE0_HARD_DENY_THRESHOLD` (0.98),
`PPS_MAX_TEXT_CHARS` (6000).

Stage 0 does not have unilateral deny power at its base threshold: a score in
`[PPS_STAGE0_THRESHOLD, PPS_STAGE0_HARD_DENY_THRESHOLD)` is "suspicious" and is
escalated to the stage-1 LLM for a second opinion (`stage: "classifier+llm"`
in the audit log) rather than auto-denied. Only scores >=
`PPS_STAGE0_HARD_DENY_THRESHOLD` are auto-denied without an LLM call — in
practice stage0 is essentially always right up there (blatant "ignore all
previous instructions" / "SYSTEM OVERRIDE" payloads score ~1.00). This avoids
false positives like a borderline 0.91 score denying an ordinary benign
message with no LLM review at all.

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
