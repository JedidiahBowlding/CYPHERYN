#!/usr/bin/env python3
"""Create a secret-free manifest for the exact running CYPHERYN deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from typing import Any


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_json_lines(value: str) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return [json.loads(line) for line in value.splitlines() if line.strip()]
    return parsed if isinstance(parsed, list) else [parsed]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--database-migration-state", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--compose-file", type=Path, action="append", required=True)
    parser.add_argument("--caddy-file", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()

    repository = args.repository.resolve()
    dirty = run(["git", "status", "--porcelain"], repository)
    if dirty:
        print("ERROR: refusing to manifest a dirty production tree", file=sys.stderr)
        return 2

    files = [path.resolve() for path in args.compose_file]
    caddy = args.caddy_file.resolve()
    for path in [*files, caddy, args.env_file.resolve()]:
        if not path.is_file():
            print(f"ERROR: required deployment file is missing: {path}", file=sys.stderr)
            return 2

    compose = ["docker", "compose", "--env-file", str(args.env_file.resolve())]
    for path in files:
        compose.extend(["-f", str(path)])

    running = parse_json_lines(run([*compose, "ps", "--format", "json"], repository))
    images: dict[str, dict[str, Any]] = {}
    for container in running:
        image = str(container.get("Image", ""))
        if not image or image in images:
            continue
        inspection = json.loads(run(["docker", "image", "inspect", image], repository))[0]
        images[image] = {
            "id": inspection.get("Id"),
            "repo_digests": sorted(inspection.get("RepoDigests") or []),
        }

    manifest = {
        "schema": "cypheryn-deployment-manifest/v1",
        "application_version": args.version,
        "deployed_at_utc": datetime.now(timezone.utc).isoformat(),
        "operator": args.operator,
        "git_commit": run(["git", "rev-parse", "HEAD"], repository),
        "git_tree_clean": True,
        "database_migration_state": args.database_migration_state,
        "compose_files": {str(path): sha256_file(path) for path in files},
        "caddy_configuration": {"path": str(caddy), "sha256": sha256_file(caddy)},
        "images": images,
        "running_services": sorted(
            {
                str(container.get("Service"))
                for container in running
                if container.get("Service")
            }
        ),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
