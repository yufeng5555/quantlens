#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/local_env.sh
exec bash scripts/dev.sh
