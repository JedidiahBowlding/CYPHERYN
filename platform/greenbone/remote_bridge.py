"""Private, token-authenticated HTTP bridge for a remote Greenbone node."""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gmp_bridge import run

MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "CYPHERYN-OpenVAS-Bridge/1"

    def _authorized(self) -> bool:
        expected = os.environ.get("OPENVAS_BRIDGE_TOKEN", "")
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return len(expected) >= 32 and hmac.compare_digest(expected, supplied)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/health" or not self._authorized():
            self._json(401, {"ok": False})
            return
        self._json(200, {"ok": True, "service": "openvas-bridge"})

    def do_POST(self) -> None:
        if self.path != "/v1/bridge" or not self._authorized():
            self._json(401, {"ok": False})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise TypeError("invalid request")
            payload["username"] = os.environ["OPENVAS_ADMIN_USERNAME"]
            payload["password"] = os.environ["OPENVAS_ADMIN_PASSWORD"]
            self._json(200, {"ok": True, "data": run(payload)})
        except Exception as exc:  # noqa: BLE001 - HTTP trust boundary
            self._json(502, {"ok": False, "error": str(exc)[:300]})

    def log_message(self, format: str, *args: object) -> None:
        # Do not log request bodies, authorization headers, or credentials.
        print(f"openvas-bridge {self.client_address[0]} {format % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9393), Handler).serve_forever()
