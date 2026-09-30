#!/usr/bin/env bash
# Source this from a launcher; never infer trust or auto-register at startup.
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$TASK_ROOT/.venv/bin/python" "$TASK_ROOT/scripts/prepare_local_runtime.py" --check
source "$TASK_ROOT/var/local-runtime/env.sh"
export NEXT_TELEMETRY_DISABLED=1
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1 NUMEXPR_NUM_THREADS=1
export PYTHONPATH="$TASK_ROOT/packages/strategy-schema/python:$TASK_ROOT/services/api:$TASK_ROOT/services/backtest-worker"
