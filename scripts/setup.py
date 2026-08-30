#!/usr/bin/env python3
"""Prepare a safe cross-platform CYPHERYN development environment."""

from __future__ import annotations

import argparse
import base64
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"
PLACEHOLDER = "GENERATE_WITH_PYTHON_SCRIPTS_SETUP_PY"


def generated_values() -> dict[str, str]:
    return {
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        "PLATFORM_PROVIDER_ENCRYPTION_KEY": base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode(),
        "TAXII_TOKEN": secrets.token_hex(32),
        "SCANNER_ORCHESTRATOR_TOKEN": secrets.token_urlsafe(48),
    }


def prepare_env() -> tuple[bool, str]:
    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        changed = False
        for key, value in generated_values().items():
            if f"{key}={PLACEHOLDER}" in content:
                content = content.replace(f"{key}={PLACEHOLDER}", f"{key}={value}")
                changed = True
            elif not any(line.startswith(f"{key}=") for line in content.splitlines()):
                content = f"{content.rstrip()}\n{key}={value}\n"
                changed = True
        if not changed:
            return False, ".env already exists; existing values were preserved."
        ENV_FILE.write_text(content, encoding="utf-8", newline="\n")
        return True, "Added missing generated values; all configured values were preserved."
    if not EXAMPLE.exists():
        raise RuntimeError(".env.example is missing from the repository root.")
    content = EXAMPLE.read_text(encoding="utf-8")
    values = generated_values()
    for key, value in values.items():
        content = content.replace(f"{key}={PLACEHOLDER}", f"{key}={value}")
    ENV_FILE.write_text(content, encoding="utf-8", newline="\n")
    return True, "Created .env with unique development secrets."


def compose_command() -> list[str] | None:
    docker = shutil.which("docker")
    if not docker:
        return None
    result = subprocess.run(
        [docker, "compose", "version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [docker, "compose"] if result.returncode == 0 else None


def validate_compose(command: list[str]) -> None:
    result = subprocess.run(
        [*command, "config", "--quiet"], cwd=ROOT, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError("Docker Compose validation failed. Review .env and compose.yaml.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate without starting containers")
    parser.add_argument("--start", action="store_true", help="Build and start the core stack")
    args = parser.parse_args()
    try:
        created, message = prepare_env()
        print(f"[{'PASS' if created else 'INFO'}] {message}")
        command = compose_command()
        if command is None:
            print("[FAIL] Docker with the Compose v2 plugin was not found.")
            print("Install and start Docker Desktop, then run this command again.")
            return 1
        print("[PASS] Docker Compose v2 is available.")
        validate_compose(command)
        print("[PASS] compose.yaml and .env are valid.")
        if args.start and not args.check:
            result = subprocess.run(
                [*command, "up", "-d", "--build"], cwd=ROOT, check=False
            )
            if result.returncode:
                return result.returncode
            print("\nCYPHERYN startup requested.")
            print("Application: http://localhost:3000")
            print("API docs:   http://localhost:8000/api/docs")
            print("Run: python scripts/doctor.py")
        elif not args.check:
            print("[INFO] Start with: docker compose up -d --build")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
