# SentinelScan — setup and operation

Analyze Windows EXE files with static inspection, YARA, reputation providers, and an isolated Cuckoo guest. Review the evidence, record an approval decision, and download the report. **Application login is not required.** Everyone who can reach the frontend can access the workspace and record decisions.

## Choose your setup path

| Situation | Follow |
|---|---|
| This existing `/home/n1sh/Luna` installation | [Finish the existing installation](#finish-the-existing-installation) |
| New Linux checkout, without Docker | [Local setup, step by step](#local-setup-step-by-step) |
| Application services in Docker | [Docker alternative](#docker-alternative) |
| Application already configured and verified | [Daily startup and LAN access](#daily-startup-and-lan-access) |

Use one application runtime mode at a time. Local and Docker modes use different connection URLs and separate data stores. Neither application startup nor Docker Compose creates a Windows analysis guest automatically.

## Finish the existing installation

Run commands from the repository root:

```bash
cd /home/n1sh/Luna
```

The last verification on **22 October 2026** confirmed application/LAN operation, installed Cuckoo packages, KVM, and the downloaded Windows media. The isolated host bridge/capture permissions and Windows guest/snapshot were still missing. See [verification details](docs/LOCAL_STATUS.md); run the checks below to determine the current state.

To load the latest application changes:

```bash
./stop.sh
./start
```

To finish the missing Cuckoo infrastructure, stop application services first, then follow **steps 4–7** below. The essential host setup sequence is:

```bash
./stop.sh
.venv-local/bin/python scripts/cuckoo_guest.py host-plan
sudo python3 scripts/prepare_cuckoo_host.py --install-service
.venv-local/bin/python scripts/cuckoo_local.py host-config
.venv-local/bin/python scripts/cuckoo_guest.py repair
.venv-local/bin/python scripts/cuckoo_guest.py download
.venv-local/bin/python scripts/cuckoo_guest.py build
```

`download` verifies and reuses matching media. Run `build` only when a guest is still needed; it does not overwrite or repair an existing partial VM automatically. After a successful build, complete isolation/snapshot validation, configuration, startup, and the real execution check in steps 6–7. Installing the bridge alone does not make Cuckoo ready.

Keep the existing `.env`, `.local/`, database, and sample storage. Do not copy `.env.example` over this installation or reinstall an existing VM just to restart the application.

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

Use Python 3.10 or newer for the application dependencies; this checkout was tested locally with Python 3.13, and the backend image uses 3.12. Use **Node.js 22**, matching the frontend image. If your distribution installs a different Node major version, install/select Node 22 before continuing. For an already installed nvm:

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

Setup generates missing database/Redis passwords, preserves provider keys and external-sharing policy, and saves the first previous configuration to `.local/.env.before-local`. Existing initialized databases retain their passwords. There is no application username/password to configure.

You can now run `./start` for static analysis and provider lookups, but dynamic analysis remains unavailable until steps 3–7 are complete. Stop with `./stop.sh` before preparing/reconfiguring the guest infrastructure.

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

After successful setup, set `CUCKOO_REQUIRED=true` if startup should fail whenever Cuckoo is unavailable. The default `false` allows the app to start with explicit dynamic-analysis gaps. This option only applies when `CUCKOO_AUTO_START=true`.

## Daily startup and LAN access

From the project root:

```bash
./start
```

`./start.sh` is equivalent. If file permissions were lost, use `bash start.sh`. The command is `./start`, not `/start` or a browser route. It starts PostgreSQL, Redis, migrations, the configured local Cuckoo API/core, FastAPI, Celery worker/beat, and Next.js. It checks backend dependencies, the frontend API proxy, and worker readiness. Already running managed processes are reused; restart to load backend or `.env` changes.

Open `http://HOST_LAN_IP:3100` on the other machine. Use the LAN URL printed by startup, or inspect the active Wi-Fi/Ethernet interface with `ip -br -4 address`. For example, if that interface has `172.20.10.3`, open `http://172.20.10.3:3100`. The address can change after reconnecting; do not use a Docker, VPN, or guest-bridge address unless that network is the intended client network.

| Service | Local-mode binding |
|---|---|
| Browser/frontend | `0.0.0.0:3100` by default |
| FastAPI | `127.0.0.1:8100` |
| Cuckoo 3 management API | `127.0.0.1:8090` |
| PostgreSQL | `127.0.0.1:55432` |
| Redis | `127.0.0.1:56379` |

`FRONTEND_HOST` may restrict the listener to one host interface. Permit the frontend port from your intended LAN in the host firewall, and ensure Wi-Fi client isolation allows peer access. Keep the database, queue, Cuckoo management API and guest network private. The application has no login, so LAN reachability grants workspace access.

Uploads, events, decisions, reports, and API documentation use the same frontend origin. Next proxies relative `/api/...` requests to the backend; no remote browser API URL needs to point at `localhost`. The backend accepts same-origin proxy writes and rejects foreign browser origins. Open API documentation at `http://HOST_LAN_IP:3100/api/docs`.

```bash
# Run from the host.
.venv-local/bin/python scripts/local.py status
curl --fail http://127.0.0.1:3100/health
curl --fail http://127.0.0.1:3100/api/providers/health

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

Back up the database, sample/report storage, guest artifacts and `.env` before migration or infrastructure changes. Do not delete `.local/` to repair startup. Existing jobs and historical audit actors remain; new actions use the unauthenticated shared `LAN workspace` actor. The old application username/password/session settings are unused. Provider and database credentials remain required and must stay private.

## Workflow and approval

1. Upload a Windows x86/x64 `.exe`. Unsupported extensions, DLLs, architectures, malformed headers, and excessive uploads receive explicit errors. Duplicate bytes retain their sample history and get a new analysis ID with their submitted filename.
2. PostgreSQL durably records the job; Celery beat dispatches it. Workers recheck sample hashes and persist each stage's timestamps, status, evidence, and errors.
3. Cuckoo 3 submission uses `/submit/file`, Token authentication, a matching Windows platform/version, and a configured execution deadline. Its analysis ID and task IDs are retained. Completed reports must match the submitted SHA-256 and reported task identities. Unknown POST outcomes are never blindly resubmitted.
4. The UI receives persisted status through SSE with polling fallback. Failed/unavailable/timed-out engines remain visible; a completed job can have coverage gaps.
5. Malware scoring and approval are separate. An approval recommendation includes criteria, findings, coverage gaps, reasons, and limitations. Record an explicit decision and reason in the analysis page. Approving through the API is also blocked unless the recommendation is **Approve**. Decision history is append-only in the existing review table.
6. Export JSON or print the report. JSON includes every operation, source evidence, policy snapshot, recommendation, current decision history, errors, and limitations. Stored analysis evidence is unchanged by later decisions. An unavailable report store produces an explicit error.

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

Required evidence always includes validation, hashing, static inspection, YARA, sandbox, observed processes, network capture metadata, verdict, and report. Completed flags alone do not qualify. Empty network events can represent a real capture with no traffic; absent telemetry cannot. Optional providers can be unconfigured; actual execution failures still require review. Disabling the reputation requirement is an explicit policy choice, not a workaround for missing sandbox evidence.

Malware policy 1.1 scores VT malicious/suspicious counts, Hybrid malicious/suspicious verdicts, YARA matches, observed high-severity behavior, and Cuckoo 3 task scores (9–10 adds 70; 6–8 adds 30; positive scores below 6 add 10). Scores ≥60 are likely malicious; ≥20 suspicious. A lower score requires configured coverage/reputation for a likely-benign finding. AI indicators contribute no malware points.

**No malicious behavior detected is not proof of safety or absence of vulnerabilities.** There is no CVE, dependency, or vulnerability scanner in this implementation. Reports explicitly mark vulnerability assessment as `NOT_PERFORMED`. Certificate presence also does not establish signature trust. Execution time, guest configuration, encrypted traffic, background activity, and unavailable raw telemetry limit conclusions.

## Providers and sharing

Set backend-only `VIRUSTOTAL_API_KEY` and `HYBRID_ANALYSIS_API_KEY` if needed. Settings performs real connectivity checks; configured credentials alone are not called healthy. Hash lookup may return no existing report. Sending file contents to either external provider requires both `EXTERNAL_UPLOADS_ENABLED=true` and per-job consent. Provider API credentials remain required even though application login is removed.

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

These are placeholders, not usable credentials. There are no application login settings. If converting an existing local `.env`, replace its localhost database/Redis URLs and filesystem storage settings with these Docker values while retaining provider keys. Do not run `setup-local.sh` in Docker mode: it rewrites the URLs for local processes.

Set `SANDBOX_KIND`, `CUCKOO_API_URL` and `CUCKOO_API_TOKEN` for the sandbox that the containers can actually reach. Container `127.0.0.1` refers to the container itself, so the local default `http://127.0.0.1:8090` will not reach the host's Cuckoo API. Use a separately configured, restricted management endpoint and confirm isolation before setting `SANDBOX_ISOLATION_CONFIRMED=true`. A remote API is not started by this Compose file.

### 2. Build and start

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps -a
curl --fail http://127.0.0.1:8080/health
```

Open **`http://HOST_LAN_IP:8080`** without login. Only Nginx is published; it proxies API, uploads, SSE and frontend traffic. `FRONTEND_PORT` affects local mode, not this fixed Compose port. MinIO is built from the included Dockerfile, so the first build may take longer.

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
| Guest build failed / image already exists | Preserve the partial artifacts and inspect the VMCloak error. Do not repeatedly rerun init or remove the whole `.local` directory. |
| Analysis stays queued | Confirm worker and scheduler are running with `scripts/local.py status`; inspect worker/scheduler logs and `/api/providers/health`. |
| Report says `COMPLETED_WITH_GAPS` / `REVIEW_REQUIRED` | Read engine reasons and acceptance criteria. Unavailable execution or missing reputation is not a successful clean analysis. |
| Configuration edits appear ignored | Run `./stop.sh` then `./start`, or recreate the affected Docker containers. |

[API reference](docs/API.md) · [Security boundary](docs/SECURITY.md) · [Worker semantics](workers/README.md)
