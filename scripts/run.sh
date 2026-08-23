#!/usr/bin/env bash
# Start pps. Uses the models venv (needed for the stage-0 classifier) when it
# exists, otherwise plain python3 (stage-1-only mode, stdlib is enough).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && set -a && . ./.env && set +a
PY=python3
[ -x "$HOME/models/pps/venv/bin/python" ] && PY="$HOME/models/pps/venv/bin/python"
export PYTHONPATH=src
exec "$PY" -m pps
