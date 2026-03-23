#!/usr/bin/env python3
"""Mock HTTP server for vk-bulk-apply-sync.sh tests.

Supports dynamic fixture switching via POST /test/load-fixture.
Bulk-apply calls are logged and retrievable via GET /test/bulk-log.
"""

import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


class MockState:
    lock = threading.Lock()
    fixtures: dict = {}
    bulk_apply_log: list = []

    @classmethod
    def reset(cls, fixtures=None):
        with cls.lock:
            cls.fixtures = fixtures or {}
            cls.bulk_apply_log = []


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _respond(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = urlparse(self.path).path

        # Test helpers
        if path == "/test/bulk-log":
            with MockState.lock:
                self._respond(200, MockState.bulk_apply_log[:])
            return
        if path == "/test/ping":
            self._respond(200, {"ok": True})
            return

        with MockState.lock:
            fx = MockState.fixtures

        if path == "/api/secrets":
            self._respond(200, fx.get("lv_secrets", {"secrets": []}))
            return
        if path == "/api/agents":
            self._respond(200, fx.get("vc_agents", []))
            return

        parts = path.split("/")
        if len(parts) == 6 and parts[2] == "agents" and parts[4] == "secrets":
            key = f"vc_secret:{parts[3]}:{parts[5]}"
            if key in fx:
                self._respond(200, fx[key])
            else:
                self._respond(404, {"error": "not found"})
            return

        self._respond(404, {"error": "unknown"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path == "/test/load-fixture":
            try:
                fx = json.loads(body)
                MockState.reset(fx)
                self._respond(200, {"ok": True})
            except Exception as e:
                self._respond(400, {"error": str(e)})
            return

        if path == "/test/reset":
            MockState.reset()
            self._respond(200, {"ok": True})
            return

        if path == "/api/bulk-apply/execute":
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                payload = {}
            with MockState.lock:
                MockState.bulk_apply_log.append(payload)
                resp = MockState.fixtures.get("bulk_apply_response", {"status": "applied"})
            self._respond(200, resp)
            return

        self._respond(404, {"error": "unknown"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18900
    initial = sys.argv[2] if len(sys.argv) > 2 else ""
    if initial and os.path.exists(initial):
        with open(initial) as f:
            MockState.reset(json.load(f))
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    pid_file = f"/tmp/mock_{port}.pid"
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    print(f"Mock server on :{port} (pid {os.getpid()})", flush=True)
    server.serve_forever()
