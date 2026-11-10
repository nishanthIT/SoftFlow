#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} == --prepared-app ]]; then
  # Full setup already owns setup.lock and has installed these dependencies.
  shift
else
  python3 scripts/prepare_app.py "$@"
fi
exec .venv-local/bin/python scripts/local.py start "$@"
