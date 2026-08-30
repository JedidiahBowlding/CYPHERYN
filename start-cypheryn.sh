#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_DIR="$PROJECT_ROOT/platform/api"
FRONTEND_DIR="$PROJECT_ROOT/platform/frontend"
TAXII_DIR="$PROJECT_ROOT/platform/taxii"
RUNTIME_DIR="$PROJECT_ROOT/platform/.runtime"
API_PYTHON="$API_DIR/.venv/bin/python"
API_UVICORN="$API_DIR/.venv/bin/uvicorn"

mkdir -p "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/clamav-db"

if command -v freshclam >/dev/null 2>&1; then
  freshclam --datadir="$RUNTIME_DIR/clamav-db" >"$RUNTIME_DIR/clamav-update.log" 2>&1 || \
    echo "ClamAV signature refresh failed; retaining the existing local signatures."
fi

TAXII_TOKEN_FILE="$RUNTIME_DIR/taxii.token"
if [[ ! -s "$TAXII_TOKEN_FILE" ]]; then
  umask 077
  openssl rand -hex 32 >"$TAXII_TOKEN_FILE"
fi

if [[ ! -x "$API_PYTHON" || ! -x "$API_UVICORN" ]]; then
  echo "API environment is missing. Create platform/api/.venv and install the API first."
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
  echo "Frontend dependencies are missing. Run npm install in platform/frontend first."
  exit 1
fi

if lsof -nP -iTCP:8000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port 8000 is already in use. Stop the existing API before starting CYPHERYN."
  exit 1
fi

if lsof -nP -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port 3000 is already in use. Stop the existing frontend before starting CYPHERYN."
  exit 1
fi

API_PID=""
WORKER_PID=""
FRONTEND_PID=""
TAXII_PID=""

stop_services() {
  trap - INT TERM EXIT
  echo
  echo "Stopping CYPHERYN..."
  for process_id in "$FRONTEND_PID" "$WORKER_PID" "$API_PID" "$TAXII_PID"; do
    if [[ -n "$process_id" ]] && kill -0 "$process_id" 2>/dev/null; then
      kill "$process_id" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
  echo "CYPHERYN stopped."
}

trap stop_services INT TERM EXIT

(
  cd "$API_DIR"
  "$API_PYTHON" "$TAXII_DIR/feed_updater.py" \
    --output "$TAXII_DIR/data/objects.json" \
    --status-file "$TAXII_DIR/data/feed-status.json" \
    --api-dir "$API_DIR"
) >>"$RUNTIME_DIR/taxii-feed.log" 2>&1 || \
  echo "Trusted feed refresh failed; retaining the existing local TAXII collection."

(
  cd "$TAXII_DIR"
  exec "$API_PYTHON" server.py \
    --token-file "$TAXII_TOKEN_FILE" \
    --data-file "$TAXII_DIR/data/objects.json"
) >"$RUNTIME_DIR/taxii.log" 2>&1 &
TAXII_PID=$!

(
  cd "$API_DIR"
  exec "$API_UVICORN" intel_platform.main:app --host 127.0.0.1 --port 8000
) >"$RUNTIME_DIR/api.log" 2>&1 &
API_PID=$!

(
  cd "$FRONTEND_DIR"
  exec npm run dev
) >"$RUNTIME_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!

for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "The API stopped during startup. Review $RUNTIME_DIR/api.log"
    exit 1
  fi
  sleep 1
done

if ! curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1; then
  echo "The API did not become ready. Review $RUNTIME_DIR/api.log"
  exit 1
fi

for _ in {1..20}; do
  if curl -fsS http://127.0.0.1:9000/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -fsS http://127.0.0.1:9000/health >/dev/null 2>&1; then
  echo "The local TAXII service did not become ready. Review $RUNTIME_DIR/taxii.log"
  exit 1
fi

"$API_PYTHON" "$TAXII_DIR/bootstrap.py" "$TAXII_TOKEN_FILE"

# Bootstrap configuration before the worker begins database and delivery work.
# This prevents transient SQLite write contention from delaying startup.
(
  cd "$API_DIR"
  exec "$API_PYTHON" -m intel_platform.worker
) >"$RUNTIME_DIR/worker.log" 2>&1 &
WORKER_PID=$!

for _ in {1..90}; do
  if curl -fsS http://localhost:3000 >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "The frontend stopped during startup. Review $RUNTIME_DIR/frontend.log"
    exit 1
  fi
  sleep 1
done

if ! curl -fsS http://localhost:3000 >/dev/null 2>&1; then
  echo "The frontend did not become ready. Review $RUNTIME_DIR/frontend.log"
  exit 1
fi

echo "CYPHERYN is running."
echo "Application: http://localhost:3000"
echo "API docs:    http://127.0.0.1:8000/api/docs"
echo "Local TAXII: http://127.0.0.1:9000/.well-known/taxii2/"
echo "Logs:        $RUNTIME_DIR"

if ! curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "Local AI:    Ollama is not running; start it with: ollama serve"
else
  echo "Local AI:    Ollama is available"
fi

echo "Press Ctrl+C to stop all services."

while kill -0 "$API_PID" 2>/dev/null \
  && kill -0 "$WORKER_PID" 2>/dev/null \
  && kill -0 "$FRONTEND_PID" 2>/dev/null \
  && kill -0 "$TAXII_PID" 2>/dev/null; do
  sleep 2
done

echo "A CYPHERYN service stopped unexpectedly. Review logs in $RUNTIME_DIR"
exit 1
