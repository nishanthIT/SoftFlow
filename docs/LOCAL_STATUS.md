# Local verification status — 2026-10-07

Application URL: http://localhost:3100. Started without Docker using `./start.sh`.

## Verified

- PostgreSQL, Redis, filesystem storage, API, worker, scheduler, and frontend running.
- VirusTotal and Hybrid Analysis authenticated against live provider APIs.
- Safe compiled Windows EXE upload completed validation, hashes, PE static analysis, YARA, VirusTotal, Hybrid Analysis, AI evidence correlation, verdict, and report generation.
- Real analysis ID: `2afda8d8-ce20-4d7d-a771-0d730b2ada44`.
- Raw provider responses preserved on the backend. Hybrid Analysis summary available; full JSON report download returned access denied for this account. Complete download is **not** verified.
- Unavailable sandbox did not prevent other analysis stages completing.
- Backend regression suite: **52 passed**, one Starlette/httpx deprecation warning. Diagnostic tests cover authentication errors, rate limits, timeouts, network errors, invalid responses, and credential redaction; these failure cases use controlled test responses.
- TypeScript check and Next.js production build passed.
- `scripts/browser_local_check.py` passed against actual authenticated localhost state, without API interception: login, settings, saved analysis, report, sample list, invalid upload validation, mobile report layout, browser runtime errors, and absence of configured secrets in rendered text.

## Remaining limitations

- Cuckoo is not operational and is not configured as a connected provider.
- QEMU is not installed. Installing system dependencies needs administrator access; unattended sudo currently requires a password.
- A prepared Windows analysis VM/ISO and verified isolated network/snapshot restoration are still needed.
- Behavior and network stages remain unavailable; they must not be presented as clean or successful.
- Cuckoo 3 installation and adapter validation are unfinished. Its report format also needs normalization verification against real output before dynamic results can be claimed supported end to end.
- Browser checks of rendered text are not a comprehensive security audit.

See [README](../README.md) for startup, configuration, and troubleshooting. Do not publish private `.local/demo/` artifacts without review.
