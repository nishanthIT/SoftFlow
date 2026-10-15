#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv-local/bin/python ]]; then
  printf 'Run ./setup-local.sh first.\n' >&2
  exit 1
fi
exec .venv-local/bin/python scripts/local.py start
