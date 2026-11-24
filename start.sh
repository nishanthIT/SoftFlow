#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} == --prepared-app ]]; then
  # Full setup already owns setup.lock and has installed these dependencies.
  shift
else
  python3 scripts/prepare_app.py "$@"
fi
foreground=false
[[ -n ${pm_id:-} ]] && foreground=true
for argument in "$@"; do
  [[ $argument == --foreground ]] && foreground=true
done
if [[ $foreground == true ]]; then
  exec .venv-local/bin/python scripts/service.py run "$@"
fi
exec .venv-local/bin/python scripts/local.py start "$@"
