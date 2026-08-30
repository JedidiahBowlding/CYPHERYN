"""One-time local setup: rotate Greenbone's default password into CYPHERYN."""

from __future__ import annotations

import json
import secrets
import string
import subprocess
import urllib.request
from pathlib import Path


HERE = Path(__file__).resolve().parent
SENTINEL = HERE / ".account-secured"
API = "http://127.0.0.1:8000"
HEADERS = {
    "Content-Type": "application/json",
    "X-Dev-Subject": "local-analyst",
    "X-Dev-Email": "analyst@cypheryn.local",
}


def request(path: str, *, method: str = "GET", payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    item = urllib.request.Request(API + path, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(item, timeout=20) as response:
        return json.load(response)


def main() -> None:
    if SENTINEL.exists():
        print("Greenbone default account was already secured.")
        return
    organizations = request("/api/v1/organizations")
    if not organizations:
        raise RuntimeError("Create a CYPHERYN organization before securing Greenbone")
    organization_id = organizations[0]["id"]
    alphabet = string.ascii_letters + string.digits + "-_"
    password = "".join(secrets.choice(alphabet) for _ in range(40))

    request(
        f"/api/v1/organizations/{organization_id}/providers/openvas",
        method="PUT",
        payload={
            "enabled": True,
            "credentials": {"username": "admin", "password": password},
            "settings": {
                "kill_switch": False,
                "jobs_per_hour": 12,
                "timeout_seconds": 300,
                "failure_threshold": 3,
                "cooldown_seconds": 300,
            },
        },
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(HERE / "compose.yaml"),
            "exec",
            "-T",
            "-u",
            "gvmd",
            "gvmd",
            "sh",
            "-c",
            'IFS= read -r password; exec gvmd --user=admin --new-password="$password"',
        ],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Password rotation failed")
    verification = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(HERE / "compose.yaml"),
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "gvm-tools",
            "python3",
            "/opt/cypheryn/gmp_bridge.py",
        ],
        input=json.dumps({"action": "ping", "username": "admin", "password": password}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    lines = verification.stdout.strip().splitlines()
    response = json.loads(lines[-1]) if lines else {}
    if verification.returncode != 0 or not response.get("ok"):
        raise RuntimeError("The rotated Greenbone credential could not be verified")
    SENTINEL.write_text("CYPHERYN manages the rotated Greenbone credential.\n")
    print("Greenbone password rotated and stored in CYPHERYN's encrypted credential store.")


if __name__ == "__main__":
    main()
