"""Env-driven config. pps is deliberately dependency-free (stdlib only) unless
PPS_STAGE0_DIR is set, in which case it must run under a python that has
transformers+torch (the venv at ~/models/pps/venv)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default) or default


@dataclass(frozen=True)
class Config:
    host: str = field(default_factory=lambda: _env("PPS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("PPS_PORT", "8642")))
    # OpenAI-compatible endpoint serving the stage-1 guard LLM (llama-server).
    llm_url: str = field(default_factory=lambda: _env("PPS_LLM_URL", "http://127.0.0.1:8641"))
    llm_timeout: float = field(default_factory=lambda: float(_env("PPS_LLM_TIMEOUT", "25")))
    # Optional stage-0 fast injection classifier (HF model dir). Empty = skip.
    stage0_dir: str = field(default_factory=lambda: _env("PPS_STAGE0_DIR", ""))
    # Scores in [stage0_threshold, stage0_hard_deny_threshold) are "suspicious":
    # stage0 flags them but does NOT get unilateral deny power — they're escalated
    # to the stage-1 LLM for a second opinion (fixes false positives like borderline
    # 0.9-ish scores on benign messages). Only scores >= stage0_hard_deny_threshold
    # are auto-denied without LLM review, since in practice stage0 is essentially
    # always right up there (blatant "ignore all previous instructions" / "SYSTEM
    # OVERRIDE" payloads score ~1.00).
    stage0_threshold: float = field(default_factory=lambda: float(_env("PPS_STAGE0_THRESHOLD", "0.9")))
    stage0_hard_deny_threshold: float = field(
        default_factory=lambda: float(_env("PPS_STAGE0_HARD_DENY_THRESHOLD", "0.98")))
    # Every request + verdict is appended here (jsonl) for false-positive tuning.
    audit_log: Path = field(default_factory=lambda: Path(
        _env("PPS_AUDIT_LOG", str(Path(__file__).resolve().parents[2] / ".state" / "audit.jsonl"))))
    # Bound prefill latency on the CPU-only LLM: judge at most this many chars.
    max_text_chars: int = field(default_factory=lambda: int(_env("PPS_MAX_TEXT_CHARS", "6000")))
