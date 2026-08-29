#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not ready. Start Docker Desktop, then run this script again." >&2
  exit 1
fi

docker compose -f "$SCRIPT_DIR/compose.yaml" up -d
echo "Greenbone is starting. Run $SCRIPT_DIR/status-greenbone.sh to follow readiness."
echo "The local console will be available at https://127.0.0.1 when initialization finishes."
