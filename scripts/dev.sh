#!/usr/bin/env bash
# QuantLens Gate 5A — one-command local start (loopback only; no deployment).
# Starts: FastAPI control plane, backtest worker, Next.js web.
# Env overrides: QL_API_PORT (8000), QL_WEB_PORT (3000), QL_VAR_DIR (./var).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

API_PORT="${QL_API_PORT:-8000}"
WEB_PORT="${QL_WEB_PORT:-3000}"

export NEXT_TELEMETRY_DISABLED=1
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1 NUMEXPR_NUM_THREADS=1
export PYTHONPATH="$ROOT/packages/strategy-schema/python:$ROOT/services/api:$ROOT/services/backtest-worker"
export QL_VAR_DIR="${QL_VAR_DIR:-$ROOT/var}"
export QL_SEALED_BUILD_REGISTRY_SHA256="${QL_SEALED_BUILD_REGISTRY_SHA256:-sha256:6350a4bf95626794c1ea9afbe6fac0bf8b6305279831fb30979db9d82f690f82}"
export QL_CORRECTED_READ_EXPECTATIONS_SHA256="${QL_CORRECTED_READ_EXPECTATIONS_SHA256:-sha256:9eb50321cc31f4132c16ea37e7fd395cb0fd0b6fa3859bc4ac4b3d20fb031b6f}"
PY="$ROOT/.venv/bin/python"

if [ ! -x "$PY" ]; then
  echo "No .venv found. Run: python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-hashes.lock" >&2
  exit 1
fi

WORKER_CONTRACT="$("$PY" -c 'from quantlens_api.runtime_contract import WORKER_RUNTIME_CONTRACT; print(WORKER_RUNTIME_CONTRACT)')"
export QL_EXPECTED_WORKER_CONTRACT="$WORKER_CONTRACT"

mkdir -p "$QL_VAR_DIR"
echo "[dev] state dir: $QL_VAR_DIR"
echo "[dev] runtime contract: $WORKER_CONTRACT"
echo "[dev] starting API on http://127.0.0.1:$API_PORT (loopback only)"
# Sign-in links must land on the web app, not the API: the browser follows
# them from an inbox. The API is reached through the web proxy, so it cannot
# infer this origin from the request itself.
export QL_PUBLIC_WEB_ORIGIN="${QL_PUBLIC_WEB_ORIGIN:-http://127.0.0.1:$WEB_PORT}"
"$PY" -m uvicorn quantlens_api.app:app --host 127.0.0.1 --port "$API_PORT" >"$QL_VAR_DIR/api.log" 2>&1 &
API_PID=$!

cleanup() {
  echo; echo "[dev] stopping (api=${API_PID:-none} worker=${WORKER_PID:-none})"
  if [ -n "${WORKER_PID:-}" ]; then kill "$WORKER_PID" 2>/dev/null || true; fi
  if [ -n "${API_PID:-}" ]; then kill "$API_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# Do not start a queue consumer until the API has initialized/migrated the shared store
# and reports the exact protocol this launcher imported. This closes the normal startup
# race; the SQLite claim trigger remains the fail-closed backstop for stray old workers.
API_HEALTH="http://127.0.0.1:$API_PORT/health"
API_READY=0
for _attempt in $(seq 1 60); do
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "[dev] API exited during startup; see $QL_VAR_DIR/api.log" >&2
    tail -n 40 "$QL_VAR_DIR/api.log" >&2 || true
    exit 1
  fi
  if "$PY" -c 'import json,sys,urllib.request; payload=json.load(urllib.request.urlopen(sys.argv[1], timeout=.5)); raise SystemExit(0 if payload.get("ok") is True and payload.get("worker_runtime_contract") == sys.argv[2] else 1)' "$API_HEALTH" "$WORKER_CONTRACT" 2>/dev/null; then
    API_READY=1
    break
  fi
  sleep 0.25
done
if [ "$API_READY" -ne 1 ]; then
  echo "[dev] API runtime handshake timed out; worker was not started" >&2
  tail -n 40 "$QL_VAR_DIR/api.log" >&2 || true
  exit 1
fi

echo "[dev] starting worker"
"$PY" -m quantlens_worker.runner >"$QL_VAR_DIR/worker.log" 2>&1 &
WORKER_PID=$!

echo "[dev] starting web on http://127.0.0.1:$WEB_PORT (Ctrl-C stops everything)"
cd apps/web
NEXT_TELEMETRY_DISABLED=1 QL_API_ORIGIN="http://127.0.0.1:$API_PORT" \
  npm run dev -- --hostname 127.0.0.1 --port "$WEB_PORT"
