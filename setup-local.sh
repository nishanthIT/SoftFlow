#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv-local/bin/python ]]; then
  "${APP_PYTHON:-python3}" -m venv .venv-local
fi
.venv-local/bin/python -m pip install -r backend/requirements.txt
npm ci --prefix frontend
.venv-local/bin/python scripts/configure_local.py
printf '\nSetup complete. Run ./start.sh\n'
