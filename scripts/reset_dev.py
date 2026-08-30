#!/usr/bin/env python3
"""Delete local CYPHERYN Docker volumes after explicit confirmation."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes", action="store_true", help="Skip the interactive confirmation")
    args = parser.parse_args()
    if not args.yes:
        print("WARNING: this deletes the local database, reports, TAXII state, and quarantine data.")
        if input("Type DELETE to continue: ").strip() != "DELETE":
            print("Reset cancelled.")
            return 0
    docker = shutil.which("docker")
    if not docker:
        print("Docker was not found.", file=sys.stderr)
        return 1
    command = [docker, "compose", "down", "--volumes", "--remove-orphans"]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
