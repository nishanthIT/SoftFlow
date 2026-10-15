# SentinelScan — setup and usage guide

Analyze Windows EXE files with real static analysis, YARA, VirusTotal, Hybrid Analysis, and an independently configured Windows sandbox. Results come from backend analysis and provider responses; missing engines remain unavailable, never “clean.”

## Choose how to run

| | Without Docker | With Docker Compose |
|---|---|---|
| Browser URL | http://localhost:3100 | http://localhost:8080 |
| Start | `./start.sh` | `sudo docker compose up -d --build` |
| Stop | `./stop.sh` | `sudo docker compose down` |
| Database/queue | Local PostgreSQL and Redis processes | PostgreSQL and Redis containers |
| Sample/report storage | Private `.local/storage/` directory | MinIO named volume |
| Main configuration | Root `.env` | Root `.env` |
| Windows sandbox included? | No | No |

**Use one mode at a time.** The modes need different database URLs and storage settings. `start.sh` is the non-Docker launcher; it does not start Docker. Neither method requires an existing database: the launcher or Compose creates the application's database on first startup.

The instructions below target Linux with Bash, including Kali/Debian and Ubuntu. Native Windows/macOS startup is not supported by the local process manager.

## 1. Get the project or pull updates

### First download

Replace `YOUR_REPOSITORY_URL` with the actual Git repository URL. The project does not contain a published repository URL to substitute automatically.

```bash
git clone https://github.com/nishanthIT/SoftFlow
cd softFlow
```

If you already have the folder, simply enter it:

```bash
cd ~/softFlow
```

Check whether it is a Git checkout:

```bash
git rev-parse --is-inside-work-tree
```

If it says “not a git repository,” this is a copied/downloaded folder. You can still run the application, but cannot use `git pull` there. Clone into a **new directory** to obtain a Git checkout; preserve your existing `.env` and analysis data. Do not overwrite the working folder or create a new empty Git repository just to make `pull` work.

### Update an existing Git checkout

Stop the application using the command for your current mode. Back up `.env` and your database/storage before updating. Then:

```bash
git status --short
git pull --ff-only
```

If Git reports local changes or divergent branches, review and commit/stash your changes before proceeding. Do not discard them with a hard reset. After pulling, follow the update commands in the appropriate section below. Existing analyses are not moved automatically between Docker and local storage.

## 2. Run WITHOUT Docker

### Step 1 — install prerequisites

The local launcher needs PostgreSQL server binaries, Redis, Node.js/npm, and a Python virtual environment. Do not run the launcher as root: PostgreSQL's `initdb` refuses root execution.

On a Debian-family system:

```bash
sudo apt-get update
sudo apt-get install -y git build-essential python3-dev python3-venv postgresql redis-server nodejs npm
python3 --version
node --version
npm --version
redis-server --version
```

Use Node.js 22 for consistency with the frontend's container environment. If your distribution installs an older Node version, install Node 22 through your usual trusted Node version manager before continuing.

`setup-local.sh` creates a **Python 3.13** virtual environment if none exists. On systems providing that version:

```bash
sudo apt-get install -y python3.13 python3.13-venv python3.13-dev
```

Ubuntu 24.04 normally provides Python 3.12 instead. You can create the environment with Python 3.12 first (also the backend container's Python version), and setup will reuse it:

```bash
python3.12 -m venv .venv-local
```

Do not replace the operating system's Python or use `sudo pip`. If `.venv-local` already exists, check its interpreter with `.venv-local/bin/python --version`; setup reuses that environment.

### Step 2 — install project dependencies and generate configuration

From the project root:

```bash
bash setup-local.sh
```

This installs Python dependencies and frontend packages, then configures `.env`. It:

- Generates database/Redis passwords, `AUTH_SECRET`, and `ADMIN_PASSWORD` when absent or still marked `CHANGE_ME`.
- Preserves existing provider keys and external-upload consent policy.
- Sets local database/Redis URLs and private filesystem storage; MinIO is not required in this mode.
- Saves the first previous configuration to `.local/.env.before-local` if `.env` already existed.

Do **not** copy `.env.example` over an existing working `.env`.

### Step 3 — configure optional providers and find your login

Open the configuration locally:

```bash
nano .env
```

Find `ADMIN_USERNAME` (normally `admin`) and `ADMIN_PASSWORD`. Use those values to log in. There is no universal default password. The application's password is different from your computer's `sudo` password. Do not share the file or include it in screenshots.

Add provider keys if needed:

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_key
```

Leave unused providers blank. See the provider section below for submission consent and sandbox setup.

### Step 4 — start the application

```bash
./start.sh
```

If executable permissions were lost during copying, use `bash start.sh` (and `bash stop.sh` when stopping).

The launcher initializes PostgreSQL, creates the database, starts Redis, applies migrations, and starts FastAPI, the Celery worker/scheduler, and Next.js. It leaves these processes running in the background.

Open **http://localhost:3100** and sign in with the credentials from `.env`.

### Step 5 — check health and logs

```bash
.venv-local/bin/python scripts/local.py status
curl --fail http://127.0.0.1:8100/health
tail -n 80 .local/logs/api.log
tail -n 80 .local/logs/worker.log
tail -n 80 .local/logs/frontend.log
```

Default ports:

| Service | Local address |
|---|---|
| Frontend | `127.0.0.1:3100` |
| FastAPI | `127.0.0.1:8100` |
| PostgreSQL | `127.0.0.1:55432` |
| Redis | `127.0.0.1:56379` |

The PostgreSQL/Redis ports are fixed in the current launcher. Changing only their URLs will not change the launched server ports. Frontend/API port changes also require matching `ALLOWED_ORIGINS` and `API_INTERNAL_URL` configuration.

### Step 6 — stop, restart, or update

Stop:

```bash
./stop.sh
```

Restart after editing `.env`:

```bash
./stop.sh
./start.sh
```

After pulling code updates:

```bash
bash setup-local.sh
./start.sh
```

Stop before updating. Setup refreshes dependencies; startup applies migrations. Local data lives under `.local/`, including PostgreSQL, Redis persistence, samples/reports, and logs. Do not delete `.local/` to fix a startup problem.

## 3. Run WITH Docker Compose

### Step 1 — check Docker prerequisites

Install Docker Engine and the Compose v2 plugin for your distribution, then verify:

```bash
sudo docker version
sudo docker compose version
```

Use the distribution-specific Docker installation instructions; do not run Ubuntu repository commands on Kali/Debian. This guide assumes the commands above work. Run all Compose commands from the project root. `sudo` prompts for your computer password, never the application's password.

### Step 2 — create a Docker configuration

For a **fresh checkout without an existing `.env`**:

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Generate a separate random value for each password/secret by running this command five times:

```bash
openssl rand -hex 32
```

Use those values for `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MINIO_SECRET_KEY`, `AUTH_SECRET`, and `ADMIN_PASSWORD`. `AUTH_SECRET` needs at least 32 characters; `ADMIN_PASSWORD` needs at least 12. Hex values avoid URL-encoding issues.

Match each service password exactly in its URL:

```dotenv
POSTGRES_PASSWORD=YOUR_DATABASE_PASSWORD
DATABASE_URL=postgresql+psycopg://sentinel:YOUR_DATABASE_PASSWORD@postgres:5432/sentinel
REDIS_PASSWORD=YOUR_REDIS_PASSWORD
REDIS_URL=redis://:YOUR_REDIS_PASSWORD@redis:6379/0
MINIO_ENDPOINT=http://minio:9000
MINIO_ACCESS_KEY=sentinel-storage
MINIO_SECRET_KEY=YOUR_SEPARATE_STORAGE_SECRET
STORAGE_BACKEND=minio
STORAGE_BUCKET=sentinel
AUTH_SECRET=YOUR_SEPARATE_AUTH_SECRET
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YOUR_SEPARATE_ADMIN_PASSWORD
SECURE_COOKIES=false
YARA_PATH=/yara/rules
AI_SIGNATURES_PATH=/ai-signatures/providers.json
EXTERNAL_UPLOADS_ENABLED=false
MOCK_ANALYSIS=false
```

The example words above are placeholders, not usable passwords. Keep `SECURE_COOKIES=false` only for localhost HTTP demonstration; production HTTPS requires `true`.

**If switching from local mode**, stop with `./stop.sh`, save a private backup of `.env`, and replace the local URLs/storage/rule paths with the Docker settings above. Remove the local-only `ALLOWED_ORIGINS` setting so the backend uses its default same-origin behavior. The containers reach the database via `postgres`, Redis via `redis`, and MinIO via `minio`; `127.0.0.1` inside a container is not the host machine.

Keep provider keys in `.env`, never in frontend code. Do not run `setup-local.sh` for Docker startup: it rewrites `.env` for local processes.

### Step 3 — build and start

```bash
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps -a
```

The first build can take several minutes. Compose builds MinIO from source using `deploy/minio/Dockerfile`; it does not depend on pulling the unavailable `minio/minio` image.

`migrate` and `storage-init` are one-time initialization services. **Exited (0) is normal** for them. An exit code other than zero requires investigation before the API starts.

### Step 4 — open and verify

Open **http://localhost:8080**. Sign in using `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.

```bash
curl --fail http://127.0.0.1:8080/health
sudo docker compose logs --no-color --tail=80 migrate storage-init api worker
```

Only the proxy's loopback port 8080 is published. Docker does not use the local frontend's port 3100.

### Step 5 — stop, restart, or update

Stop while retaining database/storage volumes:

```bash
sudo docker compose down
```

After changing provider keys or other backend configuration:

```bash
sudo docker compose up -d --force-recreate api worker scheduler
```

After pulling code updates, with the previous stack stopped:

```bash
sudo docker compose up -d --build
sudo docker compose ps -a
```

Do **not** add `--volumes` or `-v` to `docker compose down` unless you intentionally want to delete stored database, Redis, and sample/report data. Existing PostgreSQL volumes retain their original password; changing `.env` does not change that database password.

### Switching back to non-Docker

```bash
sudo docker compose down
bash setup-local.sh
./start.sh
```

Setup changes `.env` back to local addresses and filesystem storage. Local and Docker analysis histories remain separate; switching modes does not migrate them.

## 4. First analysis — step by step

1. Start your chosen mode and sign in.
2. Open **Settings** to inspect actual provider connectivity. A configured key alone does not prove connectivity.
3. Open **Upload** and select a harmless Windows `.exe` you own. Do not run unknown samples on the application host.
4. Decide whether to permit external submission. Hash lookups can work without uploading file contents. Uploading bytes requires both `EXTERNAL_UPLOADS_ENABLED=true` in `.env` and explicit consent for that analysis.
5. Start analysis and follow the live engine states. Progress reflects completed/terminal engine states, not fabricated timing.
6. Open the report, expand evidence, and inspect available provider responses. Hybrid Analysis retains received raw responses; account restrictions can prevent access to the full report endpoint even when a summary is available.
7. Use **Samples** to find previous files and analysis history.

Static analysis and YARA can work without provider keys or a sandbox. Behavior/network evidence needs sandbox telemetry. Missing coverage may produce `INCONCLUSIVE`; this is an honest result, not a failed application startup. Changing configuration does not rewrite old results: submit a new analysis to test the change.

## 5. Troubleshooting

| Symptom | Check / action |
|---|---|
| Browser cannot reach localhost | Use port **3100** for local or **8080** for Docker. Check process status / `docker compose ps -a`, then startup logs. |
| `python3.13: command not found` | Install Python 3.13 and its venv package, or pre-create `.venv-local` using Python 3.12 as described above. |
| PostgreSQL binaries missing | Install the PostgreSQL server package, not only the client. The local launcher searches `/usr/lib/postgresql/*/bin`. |
| PostgreSQL password authentication failed after an edit | Restore the password matching the initialized database, or perform an intentional database password change. Do not delete data to reset a configuration error. |
| Port already in use | Inspect with `ss -ltnp`. Stop only the process you recognize; do not kill unrelated applications. |
| Login repeatedly returns to login screen | Confirm your password and `SECURE_COOKIES=false` for localhost HTTP, then restart the backend. |
| API credentials not configured | Edit the root `.env`, then restart local processes or recreate Docker backend containers. |
| Invalid API key / access denied | Verify the key and account permissions; connectivity and permission to submit/download reports are distinct. |
| Rate limited | Wait for the account quota to recover, reduce submissions, and start a new analysis later. |
| Hash not found; external upload not permitted | No report exists for that hash. Enable the global upload policy and consent only if sharing that file is permitted. |
| Hybrid Analysis HTTP 404 | Missing-hash responses are handled as no report; other 404s can indicate a report/route problem. Inspect the engine's diagnostic and raw response availability. |
| Sandbox unavailable; behavior/network unavailable | Connect an operational sandbox with a prepared Windows VM. Installing the application or an API package alone is insufficient. |
| `storage-init` failed | Run `sudo docker compose logs --tail=100 storage-init minio`. Bundled MinIO needs `STORAGE_BACKEND=minio`, not `s3` or `filesystem`. |
| MinIO `PutPublicAccessBlock` / `MalformedXML` error | Confirm `STORAGE_BACKEND=minio`, update the code, and rebuild/recreate with `sudo docker compose up -d --build`. AWS S3 public-access-block handling differs from MinIO. |
| Job remains queued | Check the worker and scheduler logs and Redis/database health; each is required in both modes. |

Do not paste `.env`, complete environment dumps, or unredacted `docker compose config` output into support messages. Use `docker compose config --quiet` for validation without printing interpolated secrets.

## What is implemented

- Authenticated upload, bounded PE header validation, SHA-256/SHA-1/MD5, duplicate detection, sample history and per-job external submission consent.
- Persistent engine states, durable database dispatch, Celery workers, per-job Redis leases, timeouts, failure isolation, and resumable completed stages.
- VirusTotal hash lookup, consent-gated upload and polling; Hybrid Analysis hash search, consent-gated submission, polling and summary retrieval; isolated CAPE/Cuckoo task submission, checkpointing, polling and JSON reports.
- PE inspection, imports/exports/resources/version data, section entropy, bounded ASCII/UTF-16 strings, certificate metadata, real YARA rules.
- Sandbox behavior/network normalization, source-preserving raw evidence, configurable deterministic AI indicators, transparent scoring, JSON reports in object storage.
- Overview, upload, live analysis, full report, sample library/history, server-managed settings, rule inspection and administration pages. No unavailable check becomes a clean result.

This is a single-administrator SOC deployment. External services and a Windows sandbox require your infrastructure and credentials. This repository does not install or certify a safe malware detonation environment automatically. Read [security boundaries](docs/SECURITY.md) and [sandbox setup](sandbox/README.md) before enabling dynamic execution.

## Provider configuration

**VirusTotal:** set `VIRUSTOTAL_API_KEY`. Hash lookup uses `/api/v3/files/{sha256}`. When absent, file upload only occurs if both `EXTERNAL_UPLOADS_ENABLED=true` and the upload consent checkbox were selected. Uploads over 32 MB use the provider upload URL endpoint. The adapter polls analyses and then fetches the actual file report. Rate limits and authorization errors remain visible engine failures. Respect your account's upload/sharing policy and licensed usage. [Official upload API](https://docs.virustotal.com/reference/files-scan).

**Hybrid Analysis:** set `HYBRID_ANALYSIS_API_KEY` and a valid account-supported `HYBRID_ENVIRONMENT_ID` (default 160; verify against your deployment/account). The adapter searches `/search/hash`, retrieves summaries, and optionally submits/polls under the same two-part consent policy. [Official API documentation](https://www.hybrid-analysis.com/docs/api/v2).

**CAPE/Cuckoo:** configure the dedicated infrastructure using [sandbox/README.md](sandbox/README.md). Set `CUCKOO_API_URL`, `CUCKOO_API_TOKEN`, `SANDBOX_KIND=cape`, `cuckoo` (legacy), or `cuckoo3`, and only then `SANDBOX_ISOLATION_CONFIRMED=true`. CAPE API layouts can vary by release; test against your installation's `/apiv2/` schema before enabling sample submission. [Official CAPE REST API](https://capev2.readthedocs.io/en/latest/usage/api.html), [guest preparation](https://capev2.readthedocs.io/en/latest/installation/guest/index.html).

For production, use a separate virtualization host for the Windows analysis guest. Network allowlisting, guest credential isolation, task timeout cleanup and verified snapshot restoration are mandatory infrastructure responsibilities.

## Rules and AI detection

Mount `.yar`/`.yara` rules beneath `yara/rules/`. Rules compile on each job, so updates need no application rebuild. Invalid rules fail the YARA stage explicitly. One clearly labeled heuristic rule ships; this is not a comprehensive malware rule feed. Review/licence community rules before deployment. `/rules` displays actual installed files.

`ai-signatures/providers.json` is the versioned provider database (11 provider/runtime groups). Update domain, SDK and endpoint arrays through code review; the worker loads the file for every analysis. Static strings and model filenames remain indicators, DNS or provider communication is SUSPECTED, and a known provider plus observed API path is DETECTED. No LLM is used. TLS encryption, unexercised code, local inference and incomplete monitoring limit confidence. Local runtime strings are not treated as executed inference.

Network and behavior views derive from actual sandbox JSON, not independent packet capture on the application host. Detailed API calls, process trees, file/registry summaries, signatures, dropped-file and screenshot metadata remain available in expandable evidence. Not all provider summaries expose all fields; absent data is not invented. Certificate presence is not signature trust verification.

## Verdict policy

Policy v1.0 adds 70 for at least five VT malicious detections (30 for one to four), 10 for VT suspicious detections, 60 for Hybrid malicious (25 for suspicious), 25 for YARA matches, and 30 for observed high-severity injection behavior. Score ≥60 is LIKELY_MALICIOUS, ≥20 is SUSPICIOUS. LIKELY_BENIGN additionally requires all designated static/reputation/dynamic coverage and supporting reputation. Otherwise INCONCLUSIVE. Every contribution names its source. AI evidence contributes zero points. Tune and validate this deliberately conservative baseline for your environment.

### What you must prepare for dynamic analysis

Neither startup method installs a functioning Windows sandbox. Prepare KVM/QEMU, an isolated analysis network, an appropriately licensed Windows guest, the sandbox guest agent/monitor, a clean disposable snapshot, processing services, and the authenticated sandbox API. Follow [sandbox infrastructure guidance](sandbox/README.md) before enabling it.

Use `SANDBOX_KIND=cape` for a CAPE `/apiv2` API URL, `cuckoo` for legacy Cuckoo API routes, or `cuckoo3` for the Cuckoo 3 API root. These API layouts are not interchangeable. The presence of a Cuckoo 3 adapter does not establish that a working Windows execution environment has been installed or tested.

Set `CUCKOO_API_URL` and `CUCKOO_API_TOKEN` on the backend. Set `SANDBOX_ISOLATION_CONFIRMED=true` only after verifying isolation and snapshot restoration. For Docker, a sandbox API bound only to the host's loopback is not reachable via container `localhost`; use an explicitly reachable, firewall-restricted management address.

A successful health request alone is insufficient. Submit a harmless EXE, verify the VM executes it, retrieve a completed report, and verify snapshot restoration before accepting unknown samples. Until that is done, demonstrate the available static/reputation features and show sandbox unavailability honestly.

## Development checks

With the local dependencies installed:

```bash
PYTHONPATH=backend .venv-local/bin/python -m pytest backend/tests -q
npm run typecheck --prefix frontend
```

Stop the local frontend before building because development and build share `.next/`:

```bash
./stop.sh
npm run build --prefix frontend
./start.sh
```

These tests/builds do not establish live provider or VM connectivity. Verify those separately with a safe file through the real UI. Optional browser smoke checks in `frontend/tests/browser_smoke.py` use explicitly intercepted empty API responses; they are UI checks, not proof of working analysis providers.

## Configuration reference

| Variable | Purpose |
|---|---|
| `DATABASE_URL`, `POSTGRES_PASSWORD` | PostgreSQL connection and initial server password; must match. |
| `REDIS_URL`, `REDIS_PASSWORD` | Redis connection and server password; must match. |
| `AUTH_SECRET` | Session signing secret, at least 32 random characters. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Application login; password at least 12 characters. |
| `SECURE_COOKIES` | `false` for localhost HTTP; `true` behind production HTTPS. |
| `VIRUSTOTAL_API_KEY`, `HYBRID_ANALYSIS_API_KEY` | Backend-only provider credentials. |
| `EXTERNAL_UPLOADS_ENABLED` | Global permission for file submission; per-analysis consent is also required. |
| `HYBRID_ENVIRONMENT_ID` | Account-supported Hybrid Analysis environment. |
| `PROVIDER_TIMEOUT` | Provider analysis timeout in seconds; default 900. |
| `CUCKOO_API_URL`, `CUCKOO_API_TOKEN`, `SANDBOX_KIND` | Sandbox management API connection and adapter choice. |
| `SANDBOX_ISOLATION_CONFIRMED` | Operator confirmation of verified isolation; not an automatic safety check. |
| `STORAGE_BACKEND` | `filesystem` locally, `minio` for bundled Compose, or `s3` for configured AWS storage. |
| `LOCAL_STORAGE_PATH` | Absolute private sample/report path for filesystem mode. |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `STORAGE_BUCKET` | S3-compatible storage configuration. |
| `YARA_PATH`, `AI_SIGNATURES_PATH` | Rule and provider-signature locations; paths differ between local and containers. |
| `MAX_UPLOAD_MB` | Upload size limit; default 32 MB. |
| `MOCK_ANALYSIS` | Keep `false`; do not demonstrate fabricated analysis results. |

`.env` and `.local/` are ignored by Git. Keep private configuration backups outside version control. Rotate any credentials you have shared publicly.

## Production operations

- Back up PostgreSQL and private object storage together; reports refer to sample hashes and analysis UUIDs. Redis persistence is enabled; queued work is recoverable from PostgreSQL.
- Run exactly one scheduler. Monitor `/health`, authenticated `/health/providers`, worker logs, failed jobs, disk space, provider rate limits and sandbox restoration. Worker stage logs include analysis IDs and statuses without secret values.
- Configure a centralized log collector/error alerting service in your environment. Provider configuration is distinct from connectivity; do not label a configured provider healthy without a real request.
- Add retention and deletion policies appropriate to your organization. This release does not automatically delete evidence or implement an analyst-review workflow despite retaining a migration table for future reviews.
- Pin and scan container images, patch dependencies, rotate keys, limit outbound worker destinations, use encryption at rest, replace MinIO bootstrap credentials with least-privilege identities and independently review the system before production exposure.
- Local sandbox teardown/restore is performed by CAPE's machinery, not by a web application endpoint. Quarantine guests on restore failure.

[API reference](docs/API.md) · [Security model](docs/SECURITY.md) · [Worker semantics](workers/README.md)

