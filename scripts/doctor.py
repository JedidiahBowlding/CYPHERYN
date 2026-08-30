#!/usr/bin/env python3
"""Report SignalTrace environment health without printing secret values."""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
REQUIRED = {"POSTGRES_PASSWORD", "PLATFORM_PROVIDER_ENCRYPTION_KEY", "TAXII_TOKEN"}
PLACEHOLDER = "GENERATE_WITH_PYTHON_SCRIPTS_SETUP_PY"


def result(level: str, label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"[{level}] {label}{suffix}")


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def compose_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    return subprocess.run(
        [docker, "compose", "version"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def reachable(url: str, attempts: int = 3) -> bool:
    for attempt in range(attempts):
        try:
            with urlopen(url, timeout=3) as response:
                return 200 <= response.status < 400
        except (OSError, URLError):
            if attempt + 1 < attempts:
                time.sleep(1)
    return False


def port_value(values: dict[str, str], name: str, default: int) -> int:
    try:
        return int(values.get(name, str(default)))
    except ValueError:
        return default


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def configured_path(values: dict[str, str], name: str, default: str) -> Path:
    value = Path(values.get(name, default))
    return value if value.is_absolute() else ROOT / value


def integrity_anchor_ready(key_directory: Path, anchor_directory: Path, compose: bool) -> bool:
    """Verify anchor storage without weakening private-key directory permissions."""
    try:
        return (key_directory / "active-key.json").is_file() and anchor_directory.is_dir()
    except PermissionError:
        if not compose:
            return False
        check = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "worker",
                "python",
                "-c",
                (
                    "from pathlib import Path; "
                    "raise SystemExit(0 if "
                    "Path('/run/secrets/signaltrace-anchor/active-key.json').is_file() and "
                    "Path('/anchors').is_dir() else 1)"
                ),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return check.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Skip live service checks")
    args = parser.parse_args()
    failures = 0
    print("SignalTrace Environment Check\n")
    for executable in ("git", "docker"):
        available = shutil.which(executable) is not None
        result("PASS" if available else "FAIL", executable.title())
        failures += int(not available)
    compose = compose_available()
    result("PASS" if compose else "FAIL", "Docker Compose v2")
    failures += int(not compose)
    values = read_env()
    if values:
        result("PASS", ".env")
    else:
        result("FAIL", ".env", "Run: python scripts/setup.py")
        failures += 1
    missing = sorted(
        key for key in REQUIRED if not values.get(key) or values.get(key) == PLACEHOLDER
    )
    if missing:
        result("FAIL", "Required configuration", ", ".join(missing))
        failures += 1
    elif values:
        result("PASS", "Required configuration", "values present and hidden")
    anchoring_enabled = values.get("PLATFORM_INTEGRITY_ANCHOR_ENABLED", "true").lower() in {
        "1",
        "true",
        "yes",
    }
    key_directory = configured_path(
        values, "PLATFORM_ANCHOR_KEY_DIR", "platform/.runtime/anchor-keys"
    )
    anchor_directory = configured_path(
        values, "PLATFORM_ANCHOR_STORE_DIR", "platform/.runtime/anchors"
    )
    anchor_ready = integrity_anchor_ready(key_directory, anchor_directory, compose)
    result(
        "PASS" if anchor_ready else ("FAIL" if anchoring_enabled else "WARN"),
        "External integrity anchoring",
        "active signing key and independent store available"
        if anchor_ready
        else "run docker compose up to initialize the signing key",
    )
    failures += int(anchoring_enabled and not anchor_ready)
    if args.offline:
        result("WARN", "Live services", "offline checks skipped")
    else:
        checks = [
            ("API", port_value(values, "API_PORT", 8000), "/health/ready"),
            ("Frontend", port_value(values, "FRONTEND_PORT", 3000), "/"),
            ("Local TAXII", port_value(values, "TAXII_PORT", 9000), "/health"),
        ]
        for label, port, path in checks:
            healthy = reachable(f"http://127.0.0.1:{port}{path}")
            detail = f"http://localhost:{port}{path}"
            result("PASS" if healthy else "FAIL", label, detail)
            failures += int(not healthy)
        ollama_port = 11434
        result(
            "PASS" if reachable(f"http://127.0.0.1:{ollama_port}/api/tags") else "WARN",
            "Optional Ollama",
            "available" if port_open(ollama_port) else "not running",
        )
        spiderfoot_port = port_value(values, "SPIDERFOOT_PORT", 5001)
        result(
            "PASS" if port_open(spiderfoot_port) else "WARN",
            "Optional SpiderFoot",
            "profile running" if port_open(spiderfoot_port) else "profile disabled",
        )
        if compose:
            running = subprocess.run(
                ["docker", "compose", "ps", "--status", "running", "--services"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.splitlines()
            enabled = "scanner-orchestrator" in running
            result(
                "PASS" if enabled else "WARN",
                "Trusted scanner orchestrator",
                "profile running; worker has no Docker socket"
                if enabled
                else "profile disabled",
            )
    print(f"\nResult: {'healthy' if failures == 0 else f'{failures} required check(s) failed'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
