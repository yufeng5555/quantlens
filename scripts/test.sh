#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/local_env.sh
.venv/bin/python -m pytest
(cd apps/web && npm run typecheck -- --incremental false)
