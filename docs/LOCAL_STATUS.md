# Verification — 22 October 2026

The application is reachable at `http://172.20.10.3:3100` on this host's active Wi-Fi address. Application login, session cookies, credential validation, page guards and API dependencies have been removed. Provider and infrastructure credentials remain private and required where appropriate. Existing samples, analyses and audit data were preserved.

## Verified

- Backend: **94 tests passed**, one upstream Starlette/httpx deprecation warning. Tests cover unauthenticated access, same-origin writes, unsupported files, persisted jobs, provider errors, Cuckoo 3 source contracts, timeouts/resumption, evidence normalization, approval criteria, forbidden incomplete approval, decision audit/history, report storage failure and partial exports.
- Frontend: TypeScript checks and production build passed. Local dev uses `.next-dev`; builds use `.next`.
- `docker compose --env-file .env.example config --quiet`, Python compilation and `git diff --check` passed. Docker containers were not launched; the running installation is local-process mode.
- The local launcher started PostgreSQL, Redis, Cuckoo API, FastAPI, Celery worker/beat and the LAN-bound frontend. Worker ping, API/storage health and frontend proxy checks passed.
- A real harmless executable submission through the LAN URL reached the real database/queue/worker, completed static inspection/YARA, and generated a downloadable report. Analysis ID: `3e0037e6-2443-4ff2-89bd-6557303e8ccb`. Job outcome: `COMPLETED_WITH_GAPS`; approval: `REVIEW_REQUIRED`. No successful sandbox result was fabricated.
- Browser navigation, unauthenticated pages, report downloads, invalid-file UI feedback and mobile layout passed against the LAN URL. A full browser upload → background processing → Review required decision → JSON download also passed (analysis `17198d70-0f0d-48c2-8843-a1c8fcde8ec6`). The export contains the persisted decision and assessment; results are in `.local/verification/browser-status.json`.
- Cuckoo 3.0.1 runs under Python 3.10; both sandbox environments pass `pip check`. KVM and system QEMU are available. Installed monitor files and the downloaded Windows ISO checksum were verified.
- The configured Android SDK `qemu-img` path was corrected to the system binary, with YAML backups preserved. The VMCloak helper patch's generated-Python quoting failure was corrected and the installed patch exercised successfully.

The checks against the LAN URL were executed on the host. Connectivity from a second physical machine, Wi-Fi peer isolation and inbound host firewall policy have not been independently verified.

## Remaining Cuckoo prerequisites

The authenticated Cuckoo API returns `CORE_NOT_READY`. Core cannot execute because:

1. The dedicated `ss-cuckoo0` bridge/result-server address and capture helper permissions are not installed.
2. No Windows guest, registered analysis machine or clean snapshot exists.
3. Guest-agent connectivity, actual detonation, result collection and snapshot restoration have not been verified. `SANDBOX_ISOLATION_CONFIRMED` remains false.

Host setup requires interactive sudo; `sudo -n true` returned “a password is required.” The next local command is:

```bash
sudo python3 scripts/prepare_cuckoo_host.py --install-service
```

Then follow [the managed Cuckoo 3 setup](../sandbox/README.md#managed-local-cuckoo-3-workflow), build/import the guest, check isolation/restoration, restart and run `scripts/verify_sandbox.py` without `--allow-unavailable`. The privileged boot-service installation has been prepared and syntax-checked, but not executed here.

## Restart status

A final reload was requested after the last backend policy/validation edits. Automatic approval review timed out twice before running `./stop.sh && ./start`. The user elected to run that command locally. Until that restart completes, the already running backend has the earlier fixes but not the last validation/policy refinements. The final source itself passes the tests above.

Private artifacts: `.local/verification/status.json`, `.local/verification/report.json`, `.local/verification/browser-export.json`, `.local/run/cuckoo-doctor.json`, and `.local/logs/`. The live verification script deliberately exits 2 when dynamic execution is unavailable, even if the rest of the workflow succeeds. Contract fixtures and API availability are never counted as live guest verification.
