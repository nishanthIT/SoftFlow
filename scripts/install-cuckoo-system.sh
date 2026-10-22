#!/usr/bin/env bash
# Host packages only. Does not alter firewall rules, routes or system Python.
set -euo pipefail
if [[ $(id -u) -ne 0 ]]; then
  printf 'Run sudo bash scripts/install-cuckoo-system.sh to install host packages.\n' >&2
  exit 1
fi
. /etc/os-release
case "$ID" in ubuntu|debian|kali) ;; *) printf 'Supported package managers: Ubuntu/Debian/Kali apt.\n' >&2; exit 1;; esac
apt-get update
apt-get install -y build-essential git libssl-dev libffi-dev libjpeg-dev zlib1g-dev \
  libhyperscan-dev libcapstone-dev libmagic1 yara tcpdump cabextract p7zip-full \
  genisoimage qemu-system-x86 qemu-utils libcap2-bin acl nftables
printf '\nHost packages installed. Configure KVM access, a dedicated guest network, packet capture permissions and a prepared VM as described in sandbox/README.md.\n'
