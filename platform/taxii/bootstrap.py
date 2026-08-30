"""Connect the local TAXII collection to every accessible organization."""

import json
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

API = "http://127.0.0.1:8000"
HEADERS = {"Content-Type": "application/json", "X-Dev-Subject": "local-analyst"}


def request(path: str, method: str = "GET", payload: dict | None = None):
    body = json.dumps(payload).encode() if payload is not None else None
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            with urlopen(
                Request(API + path, data=body, headers=HEADERS, method=method), timeout=30
            ) as response:
                return json.load(response)
        except (TimeoutError, URLError) as exc:
            last_error = exc
            if attempt < 4:
                time.sleep(attempt + 1)
    raise RuntimeError(f"Local TAXII bootstrap failed after retries: {last_error}")


def main() -> None:
    token = Path(sys.argv[1]).read_text().strip()
    for organization in request("/api/v1/organizations"):
        request(
            f"/api/v1/organizations/{organization['id']}/providers/taxii",
            "PUT",
            {
                "enabled": True,
                "credentials": {"token": token},
                "settings": {
                    "collection_url": "http://127.0.0.1:9000/taxii2/collections/cypheryn-local/objects/",
                    "default_ttl_days": 90,
                    "jobs_per_hour": 60,
                    "timeout_seconds": 20,
                    "failure_threshold": 3,
                    "cooldown_seconds": 300,
                },
            },
        )
    print("Local TAXII connected to CYPHERYN.")


if __name__ == "__main__":
    main()
