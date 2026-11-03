"""Minimal REST API (stdlib only) so PhishGuard can sit behind a mail gateway / browser extension / proxy."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .detector import PhishGuard
from .logger import get_logger

log = get_logger("phishguard.api")
MAX_BODY = 2_000_000


def make_server(guard: PhishGuard, host="127.0.0.1", port=8765) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            log.info("HTTP %s - %s", self.address_string(), fmt % a)

        def _send(self, code, obj):
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"status": "ok"})
            elif self.path == "/stats":
                self._send(200, guard.stats)
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > MAX_BODY:
                    return self._send(413, {"error": "payload too large"})
                data = json.loads(self.rfile.read(n) or b"{}")
                if self.path == "/scan/url":
                    return self._send(200, guard.scan_url(str(data["url"])))
                if self.path == "/scan/email":
                    return self._send(200, guard.scan_email(str(data["raw"])))
                if self.path == "/scan/html":
                    return self._send(200, guard.scan_html(str(data["html"]), str(data.get("url", ""))))
                self._send(404, {"error": "not found"})
            except (KeyError, ValueError) as ex:
                self._send(400, {"error": f"bad request: {ex}"})
            except Exception as ex:  # never leak a stack trace to clients
                log.exception("internal error")
                self._send(500, {"error": "internal error"})

    return ThreadingHTTPServer((host, port), H)


def start_background(guard, host="127.0.0.1", port=0):
    srv = make_server(guard, host, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
