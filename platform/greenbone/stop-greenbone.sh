#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -f "$SCRIPT_DIR/compose.yaml" stop
echo "Greenbone stopped. Scan data and feeds remain in Docker volumes."
