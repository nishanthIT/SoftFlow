# SentinelScan — setup and operation

Analyze Windows EXE files with static inspection, YARA, reputation providers, and an isolated Cuckoo guest. Review the evidence, record an approval decision, and download the report. The private LAN workspace opens directly without a login. Static analysis and reports work independently of Cuckoo.

## Start the private LAN application

```bash
cd ~/Luna
npm start
```

Open **http://localhost:3100**. No username or password is required. The website uses plain HTTP on your private LAN; no website certificates or HTTPS proxy are installed.

This command prepares the application Python environment and locked frontend dependencies as needed, applies database migrations, and starts the website, workers and cleanup scheduler. With the current `SANDBOX_ENABLED=false` setting it does **not** install, build or start Cuckoo or a Windows VM, and does not require sandbox readiness. The existing local PostgreSQL and Redis host packages must be installed. No sudo is needed on the prepared host.

Choose **SSL expiry checker** in the sidebar or open `http://localhost:3100/ssl-checker`. Upload a UTF-8 `.txt` file with one public domain per line (up to 500 unique domains, 256 KiB), watch progress and select **Download Excel**. The original script's nine report columns, status colors, filters and frozen header are preserved; a summary sheet is included. Expired/untrusted certificates and connection failures retain their details. Try [the example domain list](docs/ssl-domains-example.txt). Uploaded text is discarded after parsing, results expire after seven days, and Excel exports are generated in memory. This feature uses DNS/TLS connections independently of Cuckoo and website HTTPS.

On **New analysis**, the **Software vulnerability lookup** fields let you supply a software name and version, such as `7-Zip` and `16.00`. Leave them empty to read executable version resources automatically. Missing product strings can also yield an explicitly unverified filename candidate. NVD's product dictionary resolves exact product names outside the local catalog; ambiguous publishers remain candidates. The analysis compares published affected-version ranges and displays applicable CVEs, severity, references and provider errors in **Software vulnerability assessment**, the JSON export and the PDF report. A supplied identity describes what to compare; it does not authenticate the uploaded binary. Existing completed analyses have **Check or correct software name and version**, which starts a new analysis while retaining the previous report.

Executable upload, static analysis, YARA, configured reputation services, review history and PDF/JSON reports remain available. Reports explicitly label sandbox, behavior and network evidence as unavailable while the sandbox is disabled. Provider failures do not prevent the remaining analysis steps or report generation. No successful sandbox execution is simulated.

`npm start` uses a cached production frontend build, with separate analysis, SSL and maintenance workers. A supervisor restarts crashed services automatically and limits managed log growth. Repeating startup reuses unchanged processes. Changes to backend code or runtime configuration drain workers before restarting them. Stop with `npm stop`; check services with `npm run status`. Use `npm run dev` only for development.

For automatic startup when your user session starts:

```bash
npm run service:install
```

The user service also recovers the supervisor after a crash and uses the Node installation selected when it was installed. Rerun `npm run service:install` if you change Node installations. To keep it running after logout and start it before login, run `sudo loginctl enable-linger "$USER"` once in your terminal. Without that host setting, automatic startup is tied to your user session. Check it with `systemctl --user status sentinelscan`. Stop automatic operation with `systemctl --user disable --now sentinelscan`.

Cuckoo can be enabled later with `SANDBOX_ENABLED=true` after provisioning and verification. The application never treats missing execution evidence as a clean sandbox result.

## Optional automated Cuckoo setup

From the repository root, as the normal application user:

```bash
npm run setup -- --accept-windows-license
npm start
```

The license flag confirms authorization to install Windows from the configured ISO. Setup asks for sudo authentication in your terminal, installs only missing host packages, reuses pinned environments and verified media, configures the isolated bridge and boot service, builds or reuses the Windows guest, and verifies restoration with a harmless marker across two boots. It enables execution only after host isolation and snapshot checks pass, then runs a harmless end-to-end analysis. Existing partial VM builds are preserved and reported for repair. Setup stops an idle managed application; queued/running analyses prevent provisioning.

`npm start` prepares missing or changed application dependencies, applies migrations and checks the application services. It attempts Cuckoo startup only when `SANDBOX_ENABLED=true`. In that configuration, `CUCKOO_REQUIRED=true` makes unavailable execution fail startup; `--allow-degraded` allows partial operation. It does not rebuild guests. Use `npm stop` to stop managed processes, and `npm run setup -- --check` for a read-only sandbox prerequisite report.

Current verification and remaining host blockers are recorded in [implementation verification](docs/IMPLEMENTATION_VERIFICATION.md). The detailed manual paths below remain available for troubleshooting and remote sandbox deployments.

## Choose your setup path

| Situation | Follow |
|---|---|
| This existing `/home/n1sh/Luna` installation | [Finish the existing installation](#finish-the-existing-installation) |
| New Linux checkout, without Docker | [Local setup, step by step](#local-setup-step-by-step) |
| Application services in Docker | [Docker alternative](#docker-alternative) |
| Application already configured and verified | [Daily startup and LAN access](#daily-startup-and-lan-access) |

Use one application runtime mode at a time. Local and Docker modes use different connection URLs and separate data stores. Neither application startup nor Docker Compose creates a Windows analysis guest automatically.

## Finish the existing installation

Preserve the existing `.env`, `.local/`, database and sample storage. Run the automated setup command above in your terminal; verified media and complete snapshots are reused. Missing sudo authentication stops setup before host changes. See [implementation verification](docs/IMPLEMENTATION_VERIFICATION.md) for the current checks and blockers.

## Local setup, step by step

The local launcher targets Linux. Host package scripts support Debian, Kali, and Ubuntu; the pinned Cuckoo baseline documents Ubuntu 22.04. Guest-build compatibility on other distributions still needs verification. Run setup and startup as your normal user; use `sudo` only for the host commands explicitly shown. PostgreSQL initialization cannot run as root.

### 1. Install application prerequisites

From your project directory:

```bash
sudo apt-get update
sudo apt-get install -y git build-essential python3-dev python3-venv \
  postgresql redis-server nodejs npm curl openssl iproute2
python3 --version
node --version
npm --version
```

Use Python 3.10 or newer for the application dependencies; this checkout was tested locally with Python 3.13, and the backend image uses 3.12. The frontend container uses **Node.js 22**; the current native installation was also verified with **Node.js 24.19.0**. Keep the selected Node/npm installation consistent between terminal startup and the user service. To select the container baseline with an already installed nvm:

```bash
nvm install 22
nvm use 22
```

Cuckoo has its own **Python 3.10** environment, prepared in step 3. Do not install its lockfile into the application's environment or replace the operating system's Python.

### 2. Prepare the application

```bash
bash setup-local.sh
```

This installs Python dependencies into `.venv-local`, installs frontend packages, and creates/updates the root `.env` for local PostgreSQL, Redis, and private filesystem storage. You do not need to create the database or run migrations manually; `./start` does that.

To select a specific application Python on a **fresh** checkout, use `APP_PYTHON=python3.12 bash setup-local.sh`, for example. Setup reuses an existing `.venv-local`; changing `APP_PYTHON` does not replace it.

Setup generates missing database/Redis passwords, preserves provider keys and external-sharing policy, and saves the first previous configuration to `.local/.env.before-local`. Existing initialized databases retain their passwords. No application credentials are generated or required.

You can now run `npm start` with `SANDBOX_ENABLED=false` for static analysis and provider lookups. Steps 3–7 are optional and enable dynamic analysis. Stop with `./stop.sh` before preparing/reconfiguring the guest infrastructure.

### 3. Install Cuckoo 3 and VMCloak

```bash
sudo bash scripts/install-cuckoo-system.sh
sudo apt-get install -y gcc-mingw-w64-x86-64
bash setup-cuckoo.sh
.venv-local/bin/python scripts/cuckoo_guest.py install
```

The host installer supplies QEMU, capture tools, native build dependencies, and firewall utilities. MinGW compiles the harmless verification program; it is optional if you supply your own harmless Windows executable with `verify_sandbox.py --sample`.

`setup-cuckoo.sh` installs the pinned Cuckoo release and dependencies, creates its working directory/API database, installs monitor/signature files for a new working directory, and saves a generated API token in `.env`. It enables managed local Cuckoo startup. If Python 3.10 is unavailable, the default bootstrap installs a pinned interpreter under `.local/python/` without modifying system Python.

| Component | Default location |
|---|---|
| Application Python | `.venv-local/` |
| Cuckoo Python 3.10 | `.local/cuckoo-venv/` |
| Cuckoo configuration/data | `.local/cuckoo/` |
| VMCloak Python | `.local/vmcloak-venv/` |
| VMCloak images/snapshots | `.local/vmcloak/` |
| Cuckoo dependency lockfile | `sandbox/requirements.lock` |
| VMCloak dependency lockfile | `sandbox/vmcloak-requirements.lock` |
| Pinned versions | `sandbox/versions.json` |

Network access is needed for package/source downloads. Existing Cuckoo configurations and credentials are preserved. A different interpreter or locally modified source checkout can cause setup to stop rather than silently overwrite it.

### 4. Configure the isolated guest network

Hardware virtualization must be enabled in firmware, and Linux must expose `/dev/kvm`:

```bash
ls -l /dev/kvm
.venv-local/bin/python scripts/cuckoo_guest.py host-plan
sudo python3 scripts/prepare_cuckoo_host.py --install-service
.venv-local/bin/python scripts/cuckoo_local.py host-config
ip -br address show ss-cuckoo0
```

The default bridge is `ss-cuckoo0`, with host/result-server address `192.168.30.1/24`. Host setup blocks guest forwarding and restricts guest-to-host access to the result server and replies. It also configures a restricted bridge helper, capture permissions, and KVM access for your normal user. It preserves other firewall tables and rejects overlap with another host interface's subnet.

`--install-service` requires systemd. It installs a root-owned boot service to restore these runtime settings after reboot; the application processes themselves are still started with `./start`. On a host without systemd, omit the flag and rerun host setup after each reboot before starting Cuckoo.

If the default guest subnet overlaps your LAN/VPN, choose an unused private subnet by editing `CUCKOO_GUEST_NETWORK`, `CUCKOO_RESULTSERVER_IP`, `CUCKOO_BUILD_IP`, and `CUCKOO_GUEST_IP` in `.env` **before** generating the host plan. All guest addresses must be in that subnet. Keep the guest bridge separate from the application LAN.

### 5. Create and import the Windows guest

```bash
.venv-local/bin/python scripts/cuckoo_guest.py download
.venv-local/bin/python scripts/cuckoo_guest.py build
```

Use appropriately licensed Windows media. The helper downloads/verifies the pinned media, extracts it, initializes a Windows guest through VMCloak, creates a snapshot, and imports the resulting machine into Cuckoo. Defaults are 2 guest CPUs, 4 GiB RAM, and a 64 GB virtual disk. Allow host capacity for the guest, the application, extracted installation media, base disk, and snapshot files.

Allow at least **9 GiB free on the media filesystem for a fresh ISO download/assembly alone**: the approximately 4.04 GiB download fragments are retained while a second copy is assembled and verified. Extraction, guest disks, and snapshots require additional capacity. `download` does not start a VM or allocate guest RAM. If it fails after `65/65 fragments ready` with `No space left on device`, follow [disk-space recovery](sandbox/README.md#iso-download-fails-with-no-space-left-on-device); keep the downloaded fragments for reuse.

The initial build uses `192.168.30.2`; the snapshot sequence starts at `192.168.30.10`. `CUCKOO_RAM_MB`, `CUCKOO_CPUS`, and `CUCKOO_DISK_GB` can override guest resources. Build failures must be inspected before retrying: existing partial images are not deleted automatically. See [sandbox setup](sandbox/README.md#managed-local-cuckoo-3-workflow) for recovery and alternative infrastructure.

### 6. Verify isolation and configure execution

Check guest-agent reachability, monitor/result-server connectivity, clean snapshot restoration, and that the guest cannot reach the application LAN. The supplied guest network blocks Internet access, which limits observable network behavior. **A generated snapshot or a successful API health request does not verify these properties.**

Edit the existing `.env` locally:

```bash
nano .env
```

For the managed local installation, confirm these values (preserve the token generated in step 3):

```dotenv
SANDBOX_KIND=cuckoo3
CUCKOO_AUTO_START=true
CUCKOO_API_URL=http://127.0.0.1:8090
CUCKOO_CWD=.local/cuckoo
CUCKOO_VENV=.local/cuckoo-venv
SANDBOX_PLATFORM=windows
SANDBOX_OS_VERSION=10
SANDBOX_ANALYSIS_TIMEOUT=120
PROVIDER_TIMEOUT=900
FRONTEND_HOST=0.0.0.0
```

Only after checking isolation and restoration, change `SANDBOX_ISOLATION_CONFIRMED` from `false` to `true`. No setup script sets this attestation for you. Until it is true, managed startup does not start the Cuckoo core and file execution is blocked.

Run the prerequisite check:

```bash
.venv-local/bin/python scripts/cuckoo_local.py doctor
```

Continue to execution testing only when the JSON says `"ready": true`. Failures identify missing dependencies, capture/KVM permissions, monitor files, bridge/result-server configuration, VM/snapshot files, or attestation. A ready doctor is still not proof that the guest has executed a sample.

### 7. Start and verify the complete workflow

```bash
./start
curl --fail http://127.0.0.1:3100/health
.venv-local/bin/python scripts/verify_sandbox.py
```

If the app was already running before your configuration edits, run `./stop.sh` first. The verification command compiles and submits the included harmless Windows executable, waits for actual processing, validates task/sample/report identity, and checks behavioral/network evidence. It never runs the executable on the host.

Successful dynamic verification requires **exit code 0**, `"workflow_verified": true`, and `"sandbox_verified": true` in `.local/verification/status.json`. The report is saved to `.local/verification/report.json`. Exit code 2 means execution is not verified; exit code 1 indicates a verification error. `--allow-unavailable` can exercise the partial workflow but still returns 2 without dynamic execution.

After successful setup, use `SANDBOX_ENABLED=true` and `CUCKOO_REQUIRED=true` to require sandbox readiness. With `SANDBOX_ENABLED=false`, the website starts independently and reports dynamic-analysis gaps.

## Daily startup and LAN access

From the project root:

```bash
./start
```

`./start.sh` is equivalent. If file permissions were lost, use `bash start.sh`. The command is `./start`, not `/start` or a browser route. It starts PostgreSQL, Redis, migrations, FastAPI, the dedicated workers/scheduler, the production Next.js server and recovery supervisor. Cuckoo is started only when explicitly enabled. It checks backend dependencies, the frontend API proxy, and worker readiness. Already running managed processes are reused; restart to load backend or `.env` changes.

Open `http://HOST_LAN_IP:3100` on the other machine. Use the LAN URL printed by startup, or inspect the active Wi-Fi/Ethernet interface with `ip -br -4 address`. For example, if that interface has `172.20.10.3`, open `http://172.20.10.3:3100`. The address can change after reconnecting; do not use a Docker, VPN, or guest-bridge address unless that network is the intended client network.

| Service | Local-mode binding |
|---|---|
| Browser/frontend | `0.0.0.0:3100` by default |
| FastAPI | `127.0.0.1:8100` |
| Cuckoo 3 management API | `127.0.0.1:8090` |
| PostgreSQL | `127.0.0.1:55432` |
| Redis | `127.0.0.1:56379` |

`FRONTEND_HOST` may restrict the listener to one host interface. Permit the frontend port from your intended LAN in the host firewall, and ensure Wi-Fi client isolation allows peer access. Keep the database, queue, Cuckoo management API and guest network private. Anyone who can reach the frontend can access the shared workspace, upload samples and record decisions.

Uploads, events, decisions, reports, and API documentation use the same frontend origin. Next proxies relative `/api/...` requests to the backend; no remote browser API URL needs to point at `localhost`. The backend accepts same-origin proxy writes and rejects foreign browser origins. Open API documentation at `http://HOST_LAN_IP:3100/api/docs`.

```bash
# Run from the host.
.venv-local/bin/python scripts/local.py status
curl --fail http://127.0.0.1:3100/health
# Provider details are available in Settings.

# Stop or restart after editing backend code/.env.
./stop.sh
./start
```

On the second machine, test `curl --fail http://HOST_LAN_IP:3100/health` or open that address in a browser. A successful request to the LAN IP from the host alone does not prove peer-to-peer connectivity.

`API_PORT`, `FRONTEND_PORT`, `LOCAL_POSTGRES_PORT`, and `LOCAL_REDIS_PORT` control local ports. After changing database/queue ports, stop the app and run `.venv-local/bin/python scripts/configure_local.py` to align connection URLs. Startup derives `API_INTERNAL_URL` from `API_PORT`. Substitute your configured frontend port in these examples if it is not 3100.

## Updates, logs and existing data

After reviewing/pulling code updates, refresh application dependencies and restart:

```bash
./stop.sh
bash setup-local.sh
./start
```

Only rerun Cuckoo/VMCloak installers when those components need updating; use the repository's pinned versions. Routine application updates do not require rebuilding a guest.

```bash
tail -n 80 .local/logs/api.log
tail -n 80 .local/logs/worker.log
tail -n 80 .local/logs/frontend.log
tail -n 80 .local/logs/cuckoo-api.log
tail -n 80 .local/logs/cuckoo-core.log
```

Back up the database, sample/report storage, guest artifacts and `.env` before migration or infrastructure changes. Do not delete `.local/` to repair startup. Historical audit actors remain; analysis data expires under the seven-day retention policy. New actions use the unauthenticated shared `LAN workspace` actor. The old application username/password/session settings are unused. Provider and database credentials remain required and must stay private.

## Workflow and approval

1. Upload a Windows x86/x64 `.exe`. Unsupported extensions, DLLs, architectures, malformed headers, and excessive uploads receive explicit errors. Duplicate bytes retain their sample history and get a new analysis ID with their submitted filename.
2. PostgreSQL durably records the job; Celery beat dispatches it. Workers recheck sample hashes and persist each stage's timestamps, status, evidence, and errors.
3. Cuckoo 3 submission uses `/submit/file`, Token authentication, a matching Windows platform/version, and a configured execution deadline. Its analysis ID and task IDs are retained. Completed reports must match the submitted SHA-256 and reported task identities. Unknown POST outcomes are never blindly resubmitted.
4. The UI receives persisted status through SSE with polling fallback. Failed/unavailable/timed-out engines remain visible; a completed job can have coverage gaps.
5. Malware scoring and approval are separate. An approval recommendation includes criteria, findings, coverage gaps, reasons, and limitations. Record an explicit decision and reason in the analysis page. Approving through the API is also blocked unless the recommendation is **Approve**. Decision history is append-only in the existing review table.
6. View the HTML report or download JSON/PDF. Both downloadable formats are generated automatically at completion. JSON includes every operation, source evidence, policy snapshot, recommendation, current decision history, errors, and limitations. Stored analysis evidence is unchanged by later decisions. An unavailable report store produces an explicit error.

| Recommendation | Criteria |
|---|---|
| Approve | Completed job, required engines with usable evidence, no failed/timed-out stage, likely-benign malware assessment, no adverse findings, score within acceptance threshold, and configured reputation support |
| Reject | Complete required evidence and score at or above rejection threshold |
| Review required | Incomplete, unsupported, failed, timed out, missing/empty evidence, inconclusive assessment, intermediate risk, or insufficient reputation |

Configuration is captured in each new verdict. Changing it does not silently change existing recommendations. Historical jobs predating policy snapshots use the current policy when viewed.

```dotenv
APPROVAL_MAX_SCORE=0
APPROVAL_REJECT_SCORE=60
APPROVAL_REQUIRE_REPUTATION=true
APPROVAL_MIN_REPUTATION_ENGINES=20
```

Required evidence includes validation, hashing, static inspection, YARA, vulnerability matching, sandbox, observed processes, network and DNS capture metadata, verdict, and report. Completed flags alone do not qualify. Empty network events can represent a real capture with no traffic; absent telemetry cannot. Optional providers can be unconfigured; actual execution failures still require review. Disabling the reputation requirement is an explicit policy choice, not a workaround for missing sandbox evidence.

Malware policy 1.1 scores VT malicious/suspicious counts, Hybrid malicious/suspicious verdicts, YARA matches, observed high-severity behavior, and Cuckoo 3 task scores (9–10 adds 70; 6–8 adds 30; positive scores below 6 add 10). Scores ≥60 are likely malicious; ≥20 suspicious. A lower score requires configured coverage/reputation for a likely-benign finding. AI indicators contribute no malware points.

**No malicious behavior detected is not proof of safety or absence of vulnerabilities.** Product/version advisory matching now queries NVD, CVE Program records, CISA KEV, GitHub Advisories and OSV where verified package identifiers exist. Published vendor and exploit references are preserved without executing exploits. Matches distinguish confirmed affected, potentially affected, not affected and unknown versions. Unsupported mappings or failed providers produce a partial assessment. PE identity is self-reported; this is neither an embedded dependency inventory nor proof of binary authenticity. Historical reports without a lookup retain `NOT_PERFORMED`.

`NVD_API_KEY` and `GITHUB_ADVISORIES_TOKEN` are optional backend credentials. Requests have deadlines, retry/rate limits and a 24-hour expiring cache. The curated product/package catalog is `backend/app/software_catalog.json`; unverified names never become confirmed product mappings. There is no vulnerability-age cutoff. Known vulnerabilities require approval review separately from the malware score.

Uploads support an exact 2 GiB file (2,147,483,648 bytes) using checksummed, resumable 8 MiB chunks. The browser fingerprints the selected file, reports progress/speed, and safely retries interrupted chunks. Reselect the same file to resume; inactive staging chunks expire after one hour. Worker submission and storage use files/streams. Static string extraction scans a bounded prefix and reports truncation; full-file hashes and YARA remain separate operations. External reputation uploads retain their provider-size limits.

## Providers and sharing

Set backend-only `VIRUSTOTAL_API_KEY` and `HYBRID_ANALYSIS_API_KEY` if needed. Settings performs real connectivity checks; configured credentials alone are not called healthy. Hash lookup may return no existing report. Sending file contents to either external provider requires both `EXTERNAL_UPLOADS_ENABLED=true` and per-job consent. Provider API credentials remain configured in the backend; the workspace itself has no login.

For Cuckoo use `SANDBOX_KIND=cuckoo3`, `CUCKOO_API_URL`, and `CUCKOO_API_TOKEN`. Legacy `cuckoo` and CAPE `cape` routes remain supported separately. Cuckoo 3 API/normalization is checked against the pinned source and [upstream Web API](https://cuckoo-hatch.cert.ee/static/docs/using/web-api-endpoints/). See [sandbox/README.md](sandbox/README.md) for host/guest setup and live verification.

YARA files under `yara/rules/` and AI signatures under `ai-signatures/providers.json` load for each analysis. Static SDK strings are indicators, not runtime evidence. DNS alone does not prove an API call. The supplied heuristic rules are not comprehensive malware coverage.

## Docker alternative

This starts the **application services only**. Prepare Cuckoo on a host with an isolated Windows guest using the infrastructure steps above or an existing sandbox deployment. `./start` manages local processes, not Compose containers.

### 1. Check Docker and prepare configuration

```bash
docker version
docker compose version
```

These instructions require Docker Engine and Compose v2. If your Docker installation requires sudo, use `sudo docker compose ...` for the Compose commands below. Stop any local installation with `./stop.sh` before switching modes, and keep a private backup of its `.env`.

For a fresh Docker configuration, copy the example **only if `.env` does not already exist**:

```bash
test -e .env || cp .env.example .env
chmod 600 .env
nano .env
```

Generate three separate values by running `openssl rand -hex 32` three times. Use them for the database, Redis and MinIO passwords. Replace every `CHANGE_ME` value and use the same database/Redis password in the corresponding URL:

```dotenv
POSTGRES_PASSWORD=CHANGE_ME_DATABASE_PASSWORD
DATABASE_URL=postgresql+psycopg://sentinel:CHANGE_ME_DATABASE_PASSWORD@postgres:5432/sentinel
REDIS_PASSWORD=CHANGE_ME_REDIS_PASSWORD
REDIS_URL=redis://:CHANGE_ME_REDIS_PASSWORD@redis:6379/0
MINIO_ENDPOINT=http://minio:9000
MINIO_ACCESS_KEY=sentinel-storage
MINIO_SECRET_KEY=CHANGE_ME_MINIO_SECRET
STORAGE_BACKEND=minio
STORAGE_BUCKET=sentinel
YARA_PATH=/yara/rules
AI_SIGNATURES_PATH=/ai-signatures/providers.json
FRONTEND_HOST=0.0.0.0
CUCKOO_AUTO_START=false
EXTERNAL_UPLOADS_ENABLED=false
MOCK_ANALYSIS=false
```

These are placeholders, not usable credentials. Use `APP_ENV=production`; there are no application login settings. If converting an existing local `.env`, replace its localhost database/Redis URLs and filesystem storage settings with these Docker values while retaining provider keys. Do not run `setup-local.sh` in Docker mode: it rewrites the URLs for local processes.

Set `SANDBOX_KIND`, `CUCKOO_API_URL` and `CUCKOO_API_TOKEN` for the sandbox that the containers can actually reach. Container `127.0.0.1` refers to the container itself, so the local default `http://127.0.0.1:8090` will not reach the host's Cuckoo API. Use a separately configured, restricted management endpoint and confirm isolation before setting `SANDBOX_ISOLATION_CONFIRMED=true`. A remote API is not started by this Compose file.

### 2. Build and start

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps -a
curl --fail http://127.0.0.1:8080/health
```

Open **`http://HOST_LAN_IP:8080`** directly. Only Nginx is published; it proxies API, uploads, SSE and frontend traffic. `FRONTEND_PORT` affects local mode, not this fixed Compose port. MinIO is built from the included Dockerfile, so the first build may take longer.

`migrate` and `storage-init` are one-time services: **Exited (0) is expected**. If either exits unsuccessfully, inspect:

```bash
docker compose logs --no-color --tail=80 migrate storage-init api worker
```

### 3. Stop, update, or switch back

```bash
# Stop while preserving stored data.
docker compose down

# Apply code updates.
docker compose up -d --build

# Apply only backend/provider .env changes to an already running stack.
docker compose up -d --force-recreate api worker scheduler
```

Do not add `-v` to `down` unless intentionally deleting volumes. Changing `.env` does not change passwords inside an already initialized PostgreSQL volume. Local and Docker histories remain separate; changing modes does not migrate them.

To return to local-process mode:

```bash
docker compose down
bash setup-local.sh
./start
```

If using the managed local Cuckoo instance again, restore its loopback API URL and `CUCKOO_AUTO_START=true` in `.env` before startup. Local setup preserves sandbox settings; it does not convert a remote Docker sandbox connection automatically.

## Verification

```bash
PYTHONPATH=backend .venv-local/bin/python -m pytest backend/tests -q
.venv-local/bin/python -m pytest scripts/tests -q
npm run typecheck --prefix frontend
npm run build --prefix frontend
.venv-local/bin/python scripts/cuckoo_local.py doctor
.venv-local/bin/python scripts/verify_sandbox.py
```

Local development uses `.next-dev`; production builds use `.next`. Source-contract tests use explicit fixtures and do not establish live VM execution. The live verification script compiles the harmless `sandbox/smoke.c` (requires MinGW), submits it, waits for actual processing, checks hashes/evidence/report state, and saves `.local/verification/status.json`. It exits 0 only if dynamic execution also succeeds. `--allow-unavailable` exercises the degraded workflow but exits 2 when Cuckoo execution was not verified.

Browser checks additionally require Playwright and a Chromium executable. These are optional development tools, not installed by `setup-local.sh`:

```bash
.venv-local/bin/python -m pip install playwright
```

Install Chromium for your distribution or set `CHROMIUM_PATH` to an installed Chromium executable. On Debian/Kali, the package is normally `chromium`. After the live verification command has produced `.local/verification/sentinelscan-smoke.exe`, run:

```bash
VERIFY_BASE_URL=http://HOST_LAN_IP:3100 VERIFY_UPLOAD=1 \
  .venv-local/bin/python scripts/browser_local_check.py
```

This optional degraded-mode check performs a real upload, waits for processing, records **Review required**, and downloads a report. It expects sandbox coverage to be missing. Testing the host's LAN URL locally validates binding/proxy behavior, not connectivity from a second physical machine.

## Troubleshooting

| Symptom | Check or next action |
|---|---|
| `./start` says the Python environment is missing | Run `bash setup-local.sh` from the repository root as your normal user. |
| Python dependencies fail during Cuckoo installation | Keep Cuckoo on Python 3.10 and use its separate lockfile/environment. Inspect the setup error before changing pins. |
| PostgreSQL binaries are missing | Install the PostgreSQL **server** package; the launcher searches `/usr/lib/postgresql/*/bin`. |
| PostgreSQL password mismatch | Restore the password matching the existing data directory or perform an intentional database password change. Do not delete the database. |
| Port already in use | Inspect `ss -ltnp` and stop only the service you recognize, or consistently reconfigure local service ports. |
| Host can open the app, another machine cannot | Check the active LAN IP, `FRONTEND_HOST`, port 3100 (local) or 8080 (Docker), host firewall and Wi-Fi peer isolation. |
| Page loads but API/upload fails | Request `/health` and `/api/settings` through the frontend port. Check `.local/logs/frontend.log` and `api.log`; no browser URL should target localhost on the client machine. |
| Cuckoo reports `CORE_NOT_READY` or no matching machine | Run `scripts/cuckoo_local.py doctor` with `.venv-local/bin/python`; inspect the listed prerequisites and Cuckoo core log. An API-only process cannot execute files. |
| Missing bridge, capture permissions or KVM access | Complete step 4. After reboot, check the installed host setup service or rerun the host setup command. |
| ISO download reaches `65/65`, then `OSError: [Errno 28] No space left on device` | The assembled ISO needs disk space in addition to the fragments. Follow [disk-space recovery](sandbox/README.md#iso-download-fails-with-no-space-left-on-device). Lowering guest RAM does not fix this stage. |
| Guest build failed / image already exists | Preserve the partial artifacts and inspect the VMCloak error. Do not repeatedly rerun init or remove the whole `.local` directory. |
| Analysis stays queued | Confirm worker and scheduler are running with `scripts/local.py status`; inspect worker/scheduler logs and `/api/providers/health`. |
| Redis exits with `Failed to configure LOCALE for invalid locale name` | An IDE/terminal can inherit a locale that is not installed on the host. Local startup now writes `locale-collate C` to its private Redis configuration, so `npm start` works independently of that terminal setting. No Redis data reset or system locale change is needed. |
| Report says `COMPLETED_WITH_GAPS` / `REVIEW_REQUIRED` | Read engine reasons and acceptance criteria. Unavailable execution or missing reputation is not a successful clean analysis. |
| Configuration edits appear ignored | Run `./stop.sh` then `./start`, or recreate the affected Docker containers. |

[API reference](docs/API.md) · [Security boundary](docs/SECURITY.md) · [Worker semantics](workers/README.md)

## Automatic seven-day retention

Run `npm start` **from the repository root** for normal local startup (`npm stop` stops the managed processes). This invokes the existing startup manager, applies migrations, and starts the analysis worker, a dedicated maintenance worker, and Celery beat. The maintenance queue remains available even when both analysis worker slots are busy. Compose starts the same maintenance service. Restart existing processes after upgrading so they load the new task routes and locking code.

Each analysis expires **168 hours after its original UTC creation time**, including existing records and failed analyses. The history list, sample history and analysis view show this deadline in the browser's local time. Reports and files are retained for seven days, with these safety rules:

- Expiration is checked every minute. A complete storage sweep runs every 24 hours; temporary storage is checked hourly. A daily-only job could leave expired data for another day, so the minute check handles normal expiration separately. Deletion happens on the first available check after the deadline, not exactly at the millisecond. Downtime, cleanup errors and active work can delay it.
- Queued/running analyses are never deleted. Upstream sandbox tasks must also be confirmed finished before deletion; a local timeout is insufficient. A job that finishes after its deadline becomes eligible immediately.
- The cleaner removes stored JSON/PDF/HTML reports and per-analysis artifact trees, then engine results, normalized evidence, analyst decisions, linked audit entries and the history record. The upload and sample metadata are removed when the **last** referencing analysis is deleted. A fresh or running analysis of the same hash keeps its shared upload.
- Unreferenced uploads and safe failed-job scratch files become eligible after **one hour**. Recent writes and scratch belonging to active jobs are protected. Application multipart/spooled uploads close automatically with their request; cleanup never sweeps the system `/tmp` directory or unrelated host directories.
- Files are deleted before the database references are committed away. Missing files are harmless on retry. A failed deletion leaves the analysis inventory intact, records `cleanup_retry_at`/`cleanup_error`, logs the analysis ID and error type, and retries after 24 hours. Some expired files may already have been removed when a later deletion fails. The UI marks these analyses “Cleanup pending.”
- PostgreSQL transaction advisory locks allow only one cleaner across workers/hosts/beat instances, and coordinate upload/reanalysis creation with physical deletion. They release on process/connection termination without a time-based lease expiring halfway through cleanup. All instances must share the same database and storage; SQLite is only used for unit tests.

Storage keys are restricted to `samples/<sha256>`, `reports/<analysis-uuid>.json|pdf|html`, `reports/<analysis-uuid>/...`, and `<analyses|artifacts|logs|screenshots|extracted|tmp|uploads>/<analysis-uuid>/...`. New artifact producers must use these owned directories and keep the job active until writing ends. Arbitrary paths in provider reports are never followed. Filesystem symlinks are rejected. The S3/MinIO path removes **every object version and delete marker**, not just a marker hiding the latest version. The bucket credential needs version listing/deletion and multipart listing/abort permissions in addition to the existing read/write permissions. Object Lock or denied deletion produces a retryable failure.

CAPE/Cuckoo cleanup uses each recorded task ID, verifies its current state and sample hash, and calls the service's deletion endpoint. The Cuckoo 3 route is verified against this checkout's pinned upstream source; CAPE's task-delete API must be enabled. An unavailable service, changed endpoint, unknown submission outcome or denied deletion retains the local cleanup inventory and logs a retry. For the managed local Cuckoo 3 installation, the daily sweep also collects expired unreferenced shared binaries: it waits for all application and sandbox analyses to finish, stops only its managed Cuckoo writers, inventories all remaining submitted/target hashes, and restarts and checks the API. Incomplete inventory or unmanaged writers defer deletion. External sandbox caches, reputation providers' copies, independent backups and VM snapshots remain managed by their owning systems. Do not assume this local retention policy controls third-party retention. It does delete the application's uploaded bytes and analysis artifacts, and requests deletion of the owning sandbox's per-analysis results.

Local cleanup logs are in `.local/logs/maintenance.log`; Compose logs are under the `maintenance` service. The scheduler stores its full/hourly sweep timestamps in PostgreSQL, so multiple beat instances or restarts do not repeat full sweeps continuously. Existing records older than seven days are eligible on the first check after deployment.

Verification:

```bash
PYTHONPATH=backend .venv-local/bin/python -m pytest backend/tests -q
npm run typecheck --prefix frontend
# Optional real PostgreSQL checks, using a disposable test database:
RETENTION_TEST_DATABASE_URL=postgresql+psycopg://USER@localhost/TEST_DATABASE \
  PYTHONPATH=backend .venv-local/bin/python -m pytest backend/tests/test_retention_postgres.py -q
```

Tests cover real filesystem removal, all related database tables, the exact 168-hour boundary, shared uploads, active jobs, scratch cleanup, partial deletion retries, S3 versions, sandbox deletion contracts, and independent PostgreSQL sessions competing with reanalysis. Sandbox and S3 contract fixtures do not establish deletion on a live remote sandbox or bucket.
