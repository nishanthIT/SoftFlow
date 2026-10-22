# Isolated CAPE / Cuckoo infrastructure

Sandbox infrastructure is intentionally NOT in application Compose. Run CAPE on a dedicated virtualization host and isolated analysis VLAN. Never expose KVM, libvirt, VNC, CAPE administration, or guest networks publicly.

1. Use a dedicated Ubuntu host with hardware virtualization, KVM/QEMU and libvirt. Follow the version-specific CAPE installation and guest preparation manuals linked in the main README. Confirm `/dev/kvm` and CPU virtualization availability before installation.
2. Install CAPE and its API on a management subnet. Give the application worker a firewall rule allowing only the CAPE API port. CAPE must not initiate connections to the application data network.
3. Create an appropriately licensed Windows VM. Use a disposable local user, install the CAPE guest agent and configured analysis dependencies. Disable shared folders, clipboard, host mounts and guest access to management services. Use a dedicated virtual disk and analysis network.
4. Configure CAPE's KVM machinery with the VM label, guest address, platform, and named clean snapshot. Shut down the VM and capture a clean snapshot. Verify CAPE restores it between tasks; do not enable machinery modes that retain guest state.
5. Route guest traffic through an isolated gateway (for example INetSim for controlled simulation, or a monitored restricted Internet gateway). Block RFC1918 networks, link-local/cloud metadata, application subnets, DNS rebinding destinations and management interfaces. Apply IPv6 equivalent rules. Force DNS through a dedicated resolver and capture DNS/PCAP/HTTP metadata. Use Suricata on this network if required; preserve its alerts in CAPE reports.
6. Configure CAPE processing/reporting modules for JSON, process/API behavior, network, screenshots and dropped files. Test with a harmless Windows program. Confirm stop → report collection → snapshot revert → artifact cleanup across successful, failed and timed-out tasks. Monitor machinery failure and quarantine unhealthy guests.
7. Create a limited API credential. Set `CUCKOO_API_URL=https://sandbox-management.example/apiv2`, `CUCKOO_API_TOKEN`, `SANDBOX_KIND=cape`. For legacy Cuckoo use the API root and `SANDBOX_KIND=cuckoo`.
8. Only after checking the above controls, set `SANDBOX_ISOLATION_CONFIRMED=true`.

The application observes a reported task and retrieves its report. It cannot independently attest snapshot reversion using these API responses. The adapter explicitly reports this limitation; operators must enforce and monitor restoration inside the sandbox. If restoration fails, disable task acceptance and remove the guest from service. Do not claim a VM is safe merely because a report exists.

Never pass PostgreSQL, Redis, object-storage, cloud or application credentials to the sandbox guest. Never mount the Docker socket. Worker-to-CAPE submission contains only sample bytes and execution options. Sandbox screenshots and dropped-file metadata are preserved in evidence; binary retrieval is intentionally not exposed through the web app.

## Docker and Cuckoo compatibility

Community Cuckoo container projects exist, for example https://github.com/blacktop/docker-cuckoo . They package Cuckoo services; they do not supply a ready, isolated Windows analysis VM. That project's README lists VM integration limitations, so it is not included as a working dynamic engine in this application's Compose stack.

This application's `SANDBOX_KIND=cuckoo` adapter targets the legacy Cuckoo 2 REST API. Use `SANDBOX_KIND=cape` for CAPE's `/apiv2` API, or `SANDBOX_KIND=cuckoo3` for the separate Cuckoo 3 API adapter. The adapters use different routes and authentication conventions; configure the one matching your installation. Cuckoo 3 adapter availability does not mean a working Windows VM has been installed or verified. Prepare the sandbox on isolated virtualization infrastructure and then connect its API. Installing a web/API container alone will not enable behavior or network evidence.

## Managed local Cuckoo 3 workflow

This checkout pins **Cuckoo 3.0.1 / Python 3.10** and a specific VMCloak revision in `versions.json`; application Python is separate. API routes are checked against the installed `cert-ee/cuckoo3` source and [official API documentation](https://cuckoo-hatch.cert.ee/static/docs/using/web-api-endpoints/). `requirements.lock` and `vmcloak-requirements.lock` contain separate dependency sets.

A compatible Windows guest and clean snapshot are required for real Windows behavioral analysis. The application can run static checks without them, but must report unavailable sandbox coverage. This helper is one way to provision the guest; an existing compatible Cuckoo deployment can also be used. The `download` command only prepares installation media and does not start a VM or allocate guest RAM.

On this host, Cuckoo packages, QEMU/KVM and the Windows ISO already exist. No Windows base image or snapshot has been created. The earlier core log failed on missing `br0`. The Android SDK `qemu-img` path has been replaced by the system QEMU path, and the VMCloak helper patch has been repaired. Dynamic execution has **not** been verified.

For a fresh setup (skip installed components), allow at least **9 GiB free on the ISO destination filesystem for download/assembly alone**. The pinned ISO is about 4.04 GiB; fragments and the assembled copy temporarily occupy about 8.1 GiB together. Extracted installation media, guest disks, and snapshots need additional capacity. See [disk-space recovery](#iso-download-fails-with-no-space-left-on-device) before retrying a failed download.

```bash
sudo bash scripts/install-cuckoo-system.sh
./setup-cuckoo.sh
.venv-local/bin/python scripts/cuckoo_guest.py install
.venv-local/bin/python scripts/cuckoo_guest.py download
```

Prepare the dedicated, non-routed bridge and capture helpers:

```bash
.venv-local/bin/python scripts/cuckoo_guest.py host-plan
sudo python3 scripts/prepare_cuckoo_host.py --install-service
.venv-local/bin/python scripts/cuckoo_local.py host-config
```

The privileged script adds a dedicated nftables table, `ss-cuckoo0` at `192.168.30.1/24`, a group-restricted QEMU bridge helper, capture capabilities and user KVM access. It rejects overlap with existing host interface subnets. Guest forwarding is blocked, and inbound guest-to-host access is restricted to the result server and replies. It does not replace other firewall tables. `--install-service` installs a root-owned script/plan and enables a boot service so the runtime bridge and rules return after reboot; existing guest networking must be stopped before reconfiguring it. Omitting that flag requires re-running host setup after reboot. The boot service installation requires systemd and has not been exercised on this host because sudo needs an interactive password.

The user must run the sudo command locally; do not put a sudo password in application configuration or chat. Once host setup succeeds:

```bash
.venv-local/bin/python scripts/cuckoo_guest.py repair
.venv-local/bin/python scripts/cuckoo_guest.py build
```

`build` verifies media, extracts it if needed, installs the guest via VMCloak, creates a snapshot with the supported monitor patch/agent, and imports the resulting machine into Cuckoo. It fails early if the bridge/helper/KVM are missing. It never launches an uploaded sample on the host. Guest build needs disk space, memory, compatible host QEMU, and appropriately licensed Windows media. Existing partial images are not deleted or overwritten automatically; inspect `VMCLOAK_CWD` with VMCloak before retrying a failed build.

Verify guest-agent reachability on the isolated bridge, the monitor/result-server connection, clean snapshot restoration, and guest isolation. Only then set `SANDBOX_ISOLATION_CONFIRMED=true` in `.env`. The fully blocked guest network intentionally does not provide Internet access; this limits network behavior observation.

```bash
.venv-local/bin/python scripts/cuckoo_local.py doctor
./stop.sh
./start
.venv-local/bin/python scripts/verify_sandbox.py
```

`./start` manages core (which starts its processing/result services) and the authenticated loopback API when `CUCKOO_AUTO_START=true`. The application itself has no login. `doctor` checks the pinned package environment, system tools, monitor payload, KVM/capture access, configured machine files, interfaces, result-server address, and isolation attestation. A successful doctor is a prerequisite check, not proof of guest execution or snapshot restoration.

Live verification must return success with a real matching task report, observed processes and captured network metadata. An API health response or synthetic unit fixture is not sufficient. Keep `SANDBOX_ISOLATION_CONFIRMED=false` until isolation/restoration have actually been checked. No setup script silently changes that flag.

## ISO download fails with `No space left on device`

`Windows ISO: 65/65 fragments ready` means the pieces have downloaded. The helper still needs to write a second, assembled ISO and verify its checksum. `OSError: [Errno 28] No space left on device` while writing that copy means the destination filesystem has run out of space. It is not a guest RAM allocation failure; changing `CUCKOO_RAM_MB` does not fix it.

Run these checks from the project directory on the machine where setup failed (substitute your configured media directory if `CUCKOO_WINDOWS_ISO` is customized):

```bash
df -h .local/media
df -i .local/media
du -sh .local/media/*
```

Keep `Win10_1703_English_x64.parts`: its numbered files are the resumable download. Keep an existing verified `.iso` too. The updated downloader discards only `Win10_1703_English_x64.verified-part`, the disposable assembled copy left by an interrupted or failed attempt, before checking space. It checks capacity for the remaining fragments plus assembly before downloading, checks again before assembly, and includes the underlying OS message if an operation fails. Other processes and filesystem quotas can still cause a write to fail after a successful space check.

If you are using the older script, stop any running download first, then remove only that incomplete assembled copy:

```bash
rm -f -- .local/media/Win10_1703_English_x64.verified-part
```

Free space on the filesystem shown by `df`. With all fragments already present and the failed assembled copy removed, allow at least **4.1 GiB additional free space** for assembly and the helper's margin. Do not remove the entire `.local` directory: it also contains application data, configuration, and guest artifacts. Retry normally; completed fragments are reused and a matching final ISO is reused without downloading:

```bash
.venv-local/bin/python scripts/cuckoo_guest.py download
```

If the current filesystem is too small, choose a mounted filesystem with enough capacity, move the existing `.parts` directory alongside the new ISO location, and set `CUCKOO_WINDOWS_ISO` in `.env` to that ISO's absolute path. Keep its basename unchanged so the fragment directory is found. Moving files within the same filesystem does not increase its available space. Guest extraction uses `CUCKOO_ISO_MOUNT`, and guest images use `VMCLOAK_CWD`; relocating only the ISO does not relocate those larger artifacts.
