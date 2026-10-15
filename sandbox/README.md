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
