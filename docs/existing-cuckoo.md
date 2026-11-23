# Reuse the Cuckoo server already installed on Kali

`./start` / `./start.sh` / `npm start` all use the same application launcher.
Existing mode does not install another sandbox, run VMCloak, redefine libvirt networks,
change firewall rules, reset snapshots, or rewrite Cuckoo's configuration.
CAPE and Docker are not required for this native deployment.

## One-time connection settings

After pulling this update, edit the application's existing `.env` (preserve your database
passwords and optional provider keys):

```dotenv
CUCKOO_MODE=existing
SANDBOX_KIND=cuckoo
SANDBOX_ENABLED=true
CUCKOO_REQUIRED=true
CUCKOO_AUTO_START=false
CUCKOO_START_EXISTING=true
CUCKOO_API_URL=http://127.0.0.1:8090
CUCKOO_BINARY=/home/nishanth/.venvs/cuckoo/bin/cuckoo
CUCKOO_CWD=/home/nishanth/.cuckoo
APPROVAL_REQUIRE_REPUTATION=false
DETECTION_REVIEW_THRESHOLD=3
```

Find the executable with `command -v cuckoo` inside the existing `(cuckoo)` environment.
Your confirmed Python 2.7 executable is `/home/nishanth/.venvs/cuckoo/bin/cuckoo`.
Startup discovers it from `PATH` or `~/.venvs/cuckoo/bin/cuckoo` if `CUCKOO_BINARY` is empty;
using the explicit path above also works for services without an activated environment.
No `cuckoo --version` command is used by startup.
Use the working directory containing your current `conf/cuckoo.conf`; do not point at
`~/libvirt-python-fix/src` merely because that was your terminal's current directory.
For Cuckoo 2, an empty `CUCKOO_API_TOKEN` is read from `[cuckoo] api_token` in that file.
An explicit token takes precedence. Tokens are never printed or passed on the command line.
Set `SANDBOX_ISOLATION_CONFIRMED=true` only after your guest isolation and clean-snapshot
restoration have been verified. Startup preserves that setting; an active bridge alone
is not verification of guest restoration.

On the same host, an authenticated running API is reused. If the local API port is closed,
startup launches the existing Cuckoo 2 executable and its API with that working directory.
It does not start over an occupied API port, modify a remote service, or stop processes it
did not launch. Only launched processes are recorded in the application's PID inventory.
If systemd already manages Cuckoo, set `CUCKOO_START_EXISTING=false` and let systemd own it.

For an existing Cuckoo 3 server use `SANDBOX_KIND=cuckoo3`, its actual API URL, CWD and API
token, and keep its core/API services running independently. The separate repository-managed
Cuckoo 3 installation is still available by explicitly selecting `CUCKOO_MODE=managed`.
The app never interprets Cuckoo 2 configuration as Cuckoo 3 configuration.

## Your existing libvirt network

Keep `cuckoo-isolated`, `virbr-cuckoo`, and `192.168.253.1/24` as already configured.
No startup step changes them. An inactive `default` network is not an application error.
Your posted `virsh -c qemu:///system list --all` output contains **no VM**. Before executing
samples you still need a configured guest, its running Cuckoo agent, and a clean snapshot.
For your isolated network there is no DHCP declaration, so use a suitable static guest IP
and configure the Cuckoo result server/guest interface consistently. These are existing
sandbox administration tasks; application startup will report missing prerequisites in
its local logs rather than silently install or reconfigure your VM.

Read-only checks on the server:

```bash
virsh -c qemu:///system net-list --all
virsh -c qemu:///system list --all
command -v cuckoo
/home/nishanth/.venvs/cuckoo/bin/python -m pip show cuckoo
```

After those prerequisites and connection settings are correct:

```bash
git pull
./start
```

Application dependencies and production assets are prepared automatically. Cuckoo must
advertise a Windows machine before required-sandbox startup succeeds; a busy registered
Windows guest is valid queued capacity. A successful health check is not a substitute for
a completed harmless end-to-end sample run on your server. Startup failures do not erase
existing services, network settings or data. Operator details are in `.local/logs/`;
`PYTHONPATH=backend .venv-local/bin/python -m app.check_providers` checks configured provider
settings, including the discovered Cuckoo 2 API token.

## Classification and public reports

New analyses capture policy version 2.0. VirusTotal's malicious-engine count and explicit
Hybrid Analysis `av_matched`/`av_total` counts, when supplied, are comparable counts.
The highest reported count is used; counts from overlapping scanners are not added.
Hybrid Analysis `av_detect` rates, severity scores and Cuckoo scores are not engine counts.

- Below the configured threshold (default 3): **Legitimate**, green, when required execution
  and telemetry are complete and there are no conflicting behavioral/rule findings.
- Exactly the threshold: **Manual review needed**, amber.
- Above the threshold: **Malicious**, red.
- Missing execution, empty telemetry, invalid counts, or conflicting non-count findings:
  **Manual review needed**. No result is never treated as zero detections.

Cuckoo-only scans can qualify as legitimate after completed execution with no adverse
findings; the antivirus count is left blank, not fabricated. Vulnerability remediation
and workspace approval remain separate from malware classification. Changing
`DETECTION_REVIEW_THRESHOLD` takes effect for new analyses after `./start`; historical
verdicts and approval criteria are retained as originally recorded.

Unavailable integrations and their connection diagnostics are omitted from public
settings, analysis/SSE payloads, raw-result routes, JSON exports and PDF reports. Completed
results and available partial vulnerability findings remain visible. Partial/manual-review
status remains visible without naming failed integrations. Detailed diagnostic rows stay in
the server database and logs. Legacy stored JSON reports receive the same public filtering
when downloaded; no old failure is relabeled as a clean result.

Official protocol references: [Cuckoo 2 REST API](https://cuckoo.readthedocs.io/en/latest/usage/api/)
and [Cuckoo 3 documentation](https://cuckoo-hatch.cert.ee/static/docs/).
