#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/compose.yaml")

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not ready." >&2
  exit 1
fi

"${COMPOSE[@]}" ps -a

if curl --insecure --silent --fail --max-time 5 https://127.0.0.1/ >/dev/null; then
  echo
  echo "READY: Greenbone is available at https://127.0.0.1"
else
  echo
  echo "INITIALIZING: feed data or services are still loading."
fi
