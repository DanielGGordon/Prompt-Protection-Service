#!/usr/bin/env python3
"""PreToolUse guard hook for projects bridged to Slack/voice.

Deterministic tool-boundary enforcement — this is the wall; the pps LLM judge
is only a screen. Blocks (exit 2 => tool call denied, stderr fed back to the
model): mass/system destruction, secret-file access, env dumps, and
curl-pipe-to-shell. Applies to EVERY session in the project (GUI included);
set CLAUDE_GUARD_OFF=1 in your own shell to bypass for local dev work.

Input: hook JSON on stdin ({"tool_name": ..., "tool_input": {...}}).
"""

from __future__ import annotations

import json
import os
import re
import sys

HOME = os.path.expanduser("~")

# Paths whose read/write/edit is never OK for a bridged agent session.
_SECRET_PATH = re.compile(
    r"(^|/)\.env(\.[A-Za-z0-9_.-]+)?$"          # .env, .env.local, ...
    r"|(^|/)\.ssh(/|$)"
    r"|(^|/)\.aws(/|$)"
    r"|(^|/)\.gnupg(/|$)"
    r"|(^|/)\.t3(/|$)"                           # T3 state db holds session tokens
    r"|(^|/)\.claude/\.credentials"
    r"|(^|/)\.git-credentials$"
    r"|(^|/)id_(rsa|ed25519|ecdsa)[^/]*$"
    r"|\.pem$"
    r"|(^|/)projects/slack/\.env$"               # slackcc tokens
)

_BASH_RULES: list[tuple[str, re.Pattern]] = [
    ("mass deletion outside the project", re.compile(
        r"\brm\b[^|;&]*\s-[a-zA-Z]*[rR][a-zA-Z]*\s+(--\s+)?"
        r"(/|~|\$HOME|\.\.|\*)(\s|$|/\*?\s*($|;))")),
    ("recursive find -delete at / or ~", re.compile(
        r"\bfind\s+(/|~|\$HOME)(\s|$)[^|;&]*-delete")),
    ("disk/device destruction", re.compile(
        r"\bmkfs\b|\bdd\b[^|;&]*\bof=/dev/|\bwipefs\b|\bshred\b\s+[^|;&]*/dev/")),
    ("system power/stop", re.compile(
        r"\b(shutdown|reboot|poweroff|halt)\b|\bsystemctl\s+(poweroff|halt|reboot)\b")),
    ("fork bomb", re.compile(r":\(\)\s*\{.*\|.*&.*\}")),
    ("recursive chmod/chown at / or ~", re.compile(
        r"\bch(mod|own)\b[^|;&]*-[a-zA-Z]*R[a-zA-Z]*\s+[^|;&]*\s(/|~|\$HOME)(\s|$)")),
    ("reading secret files", re.compile(
        r"\b(cat|less|more|head|tail|grep|strings|xxd|base64|cp|scp|rsync)\b[^|;&]*"
        r"(\.env\b|\.ssh/|\.aws/|id_rsa|id_ed25519|\.pem\b|\.git-credentials|\.t3/|\.gnupg/)")),
    ("environment dump", re.compile(
        r"(^|[|;&]\s*)(printenv|env)\s*($|[|;&>])")),
    ("pipe download to shell", re.compile(
        r"\b(curl|wget)\b[^|;&]*\|\s*(ba|z|da|fi)?sh\b")),
    ("editing this guard or claude settings", re.compile(
        r"claude_guard\.py|\.claude/settings(\.local)?\.json")),
]


def _deny(reason: str) -> None:
    print(f"Blocked by claude-guard: {reason}. This action is not permitted in "
          f"bridged agent sessions.", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    if os.environ.get("CLAUDE_GUARD_OFF") == "1":
        sys.exit(0)
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)  # never break tool use on malformed hook input

    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}

    if tool == "Bash":
        command = tool_input.get("command", "") or ""
        for reason, pat in _BASH_RULES:
            if pat.search(command):
                _deny(f"{reason} (command matched '{pat.search(command).group(0)[:60]}')")

    elif tool in ("Read", "Edit", "Write", "NotebookEdit"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        expanded = os.path.expanduser(path)
        if _SECRET_PATH.search(expanded) or _SECRET_PATH.search(path):
            _deny(f"secret/credential path '{path}'")
        if tool != "Read" and re.search(
                r"claude_guard\.py$|(^|/)\.claude/settings(\.local)?\.json$", expanded):
            _deny(f"modifying guard/permission config '{path}'")

    elif tool in ("Glob", "Grep"):
        target = str(tool_input.get("path") or "") + " " + str(tool_input.get("pattern") or "")
        if _SECRET_PATH.search(os.path.expanduser(target)):
            _deny("globbing/grepping a secret/credential path")

    sys.exit(0)


if __name__ == "__main__":
    main()
