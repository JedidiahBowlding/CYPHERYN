"""Small, local-only TAXII 2.1 read server for CYPHERYN."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TAXII = "application/taxii+json;version=2.1"
STIX = "application/stix+json;version=2.1"
COLLECTION_ID = "cypheryn-local"


class TaxiiHandler(BaseHTTPRequestHandler):
    server_version = "CYPHERYNTAXII/1.0"

    def _write(self, status: int, payload: dict, media_type: str = TAXII) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.token}"
        if self.headers.get("Authorization") != expected:
            self._write(401, {"title": "Unauthorized", "description": "Bearer token required"})
            return False
        return True

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        if request.path == "/health":
            self._write(200, {"status": "ready"}, "application/json")
            return
        if not self._authorized():
            return
        base = f"{self.server.public_base_url.rstrip('/')}/taxii2/"
        if request.path == "/.well-known/taxii2/":
            self._write(200, {"title": "CYPHERYN Local TAXII", "api_roots": [base]})
        elif request.path == "/taxii2/":
            self._write(
                200,
                {
                    "title": "CYPHERYN Local Threat Intelligence",
                    "description": "Locally managed STIX 2.1 intelligence",
                    "versions": ["application/taxii+json;version=2.1"],
                    "max_content_length": 10485760,
                },
            )
        elif request.path == "/taxii2/collections/":
            self._write(200, {"collections": [self._collection(base)]})
        elif request.path == f"/taxii2/collections/{COLLECTION_ID}/":
            self._write(200, self._collection(base))
        elif request.path == f"/taxii2/collections/{COLLECTION_ID}/objects/":
            objects = json.loads(self.server.data_file.read_text()).get("objects", [])
            offset = max(0, int(parse_qs(request.query).get("next", ["0"])[0]))
            page = objects[offset : offset + 500]
            following = offset + len(page)
            envelope = {"objects": page, "more": following < len(objects)}
            if envelope["more"]:
                envelope["next"] = str(following)
            self._write(200, envelope)
        else:
            self._write(404, {"title": "Not found", "description": "Unknown TAXII resource"})

    @staticmethod
    def _collection(base: str) -> dict:
        return {
            "id": COLLECTION_ID,
            "title": "CYPHERYN Local Collection",
            "description": "User-managed local CTI collection",
            "can_read": True,
            "can_write": False,
            "media_types": [STIX],
        }

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--public-base-url", default="http://127.0.0.1:9000")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--token-env", default="TAXII_TOKEN")
    parser.add_argument("--data-file", type=Path, required=True)
    parser.add_argument("--seed-data-file", type=Path)
    args = parser.parse_args()
    token = (
        args.token_file.read_text().strip()
        if args.token_file
        else os.getenv(args.token_env, "").strip()
    )
    if not token:
        parser.error(f"TAXII token is missing; set {args.token_env} or use --token-file")
    if not args.data_file.exists() and args.seed_data_file and args.seed_data_file.exists():
        args.data_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.seed_data_file, args.data_file)
    if not args.data_file.exists():
        args.data_file.parent.mkdir(parents=True, exist_ok=True)
        args.data_file.write_text('{"type":"bundle","objects":[]}')
    server = ThreadingHTTPServer((args.host, args.port), TaxiiHandler)
    server.token = token
    server.data_file = args.data_file
    server.public_base_url = args.public_base_url
    print(f"Local TAXII listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
