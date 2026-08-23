"""Tiny HTTP front for the judge. Loopback-only by default.

POST /v1/judge  {"sender": str, "policy": str, "text": str, "context": str?}
  -> {"verdict": "allow"|"deny"|"error", "category": str, "reason": str,
      "stage": "classifier"|"classifier+llm"|"llm", "latency_ms": int}
GET /healthz -> {"ok": true, "llm": "up"|"down"}

Every judgment is appended to the audit jsonl for false-positive tuning.
The service holds no credentials and touches no files besides its audit log —
that (plus running it as a systemd-sandboxed unit) is the "no permissions"
sandbox: even a fully jailbroken judge can only ever return a JSON verdict.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config
from .judge import Judge

log = logging.getLogger(__name__)


def _make_handler(cfg: Config, judge: Judge, audit_lock: threading.Lock):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # route http.server noise to logging
            log.debug(fmt, *args)

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path != "/healthz":
                self._send(404, {"error": "not found"})
                return
            llm = "down"
            try:
                with urllib.request.urlopen(f"{cfg.llm_url}/health", timeout=3) as r:
                    if r.status == 200:
                        llm = "up"
            except OSError:
                pass
            self._send(200, {"ok": True, "llm": llm})

        def do_POST(self):  # noqa: N802
            if self.path != "/v1/judge":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, {"error": "bad json"})
                return
            text = req.get("text")
            if not isinstance(text, str) or not text.strip():
                self._send(400, {"error": "missing text"})
                return
            sender = str(req.get("sender") or "unknown")
            policy = str(req.get("policy") or "No policy provided: allow only clearly benign messages.")

            verdict = judge.judge(sender, policy, text)
            log.info("judge sender=%s context=%s -> %s/%s (%sms, %s): %s",
                     sender, req.get("context", "-"), verdict["verdict"],
                     verdict["category"], verdict["latency_ms"], verdict["stage"],
                     verdict["reason"])
            self._audit(sender, req.get("context"), text, verdict)
            self._send(200, verdict)

        def _audit(self, sender: str, context, text: str, verdict: dict) -> None:
            entry = {"ts": datetime.now(timezone.utc).isoformat(),
                     "sender": sender, "context": context,
                     "text": text[:2000], **verdict}
            try:
                with audit_lock:
                    cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
                    with cfg.audit_log.open("a") as f:
                        f.write(json.dumps(entry) + "\n")
            except OSError:
                log.warning("audit write failed", exc_info=True)

    return Handler


def run(cfg: Config | None = None) -> None:
    cfg = cfg or Config()
    t0 = time.monotonic()
    judge = Judge(cfg)  # loads stage0 up front so first request isn't slow
    log.info("judge ready in %.1fs (stage0=%s)", time.monotonic() - t0,
             bool(cfg.stage0_dir))
    server = ThreadingHTTPServer((cfg.host, cfg.port),
                                 _make_handler(cfg, judge, threading.Lock()))
    log.info("pps listening on http://%s:%s (llm=%s)", cfg.host, cfg.port, cfg.llm_url)
    server.serve_forever()
