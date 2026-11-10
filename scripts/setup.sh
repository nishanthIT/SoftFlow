#!/usr/bin/env bash
# Single entry point for explicitly requested, one-time Kali provisioning.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} == --check ]]; then
  if [[ ! -x .venv-local/bin/python ]]; then
    printf '[ERROR] Application environment is missing; run npm run setup.\n' >&2
    exit 2
  fi
  exec .venv-local/bin/python scripts/provision.py --check
fi
if [[ $(id -u) == 0 ]]; then
  printf '[ERROR] Run npm run setup as the application user; setup invokes sudo only for host operations.\n' >&2
  exit 1
fi
if [[ ! -f /etc/os-release ]]; then
  printf '[ERROR] Managed setup requires Kali, Debian or Ubuntu Linux.\n' >&2
  exit 1
fi
. /etc/os-release
case "$ID" in kali|debian|ubuntu) ;; *) printf '[ERROR] Managed setup supports Kali/Debian/Ubuntu.\n' >&2; exit 1;; esac
if [[ ! -e /dev/kvm ]]; then
  printf '[ERROR] /dev/kvm is missing. Enable hardware virtualization and the host KVM module; a VM/VPS also needs nested virtualization. No VM build was attempted.\n' >&2
  exit 2
fi
printf '[SETUP] Host provisioning installs missing apt packages, creates a private non-routed guest bridge, restricts its host access, and restores those rules after reboot.\n'
printf '[SETUP] Sudo credentials are entered only in this terminal; never save them in .env.\n'
if [[ ! -t 0 ]] && ! sudo -n true 2>/dev/null; then
  printf '[ERROR] Administrator authentication is required. Run npm run setup in your interactive terminal.\n' >&2
  exit 2
fi
sudo -v
mkdir -p .local/logs .local/run
chmod 700 .local .local/logs .local/run
# flock covers shell dependency installation as well as Python provisioning.
exec 9>.local/run/setup.lock
flock -n 9 || { printf '[ERROR] Another setup is running.\n' >&2; exit 2; }
exec > >(tee -a .local/logs/setup.log) 2>&1
sudo bash scripts/install-cuckoo-system.sh
if [[ ! -x .venv-local/bin/python ]]; then
  "${APP_PYTHON:-python3}" -m venv .venv-local
fi
exec .venv-local/bin/python scripts/provision.py "$@"
