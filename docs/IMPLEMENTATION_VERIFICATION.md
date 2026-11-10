# Implementation and verification — 10 November 2026

The current native deployment runs at `http://localhost:3100` with a **production Next.js build**, direct access without login and `SANDBOX_ENABLED=false`. It uses HTTP on the private LAN as requested: website certificate generation, the private CA and the native HTTPS proxy have been removed. The domain SSL expiry checker is restored as requested, independently of website HTTPS. Cuckoo execution is unverified and unavailable evidence remains explicit in reports.

## Application authentication removal

The login screen, sign-out button, auth routes, Redis session checks and password initialization were removed at the user's request. Both production and development open the shared LAN workspace directly. Uploads, history, reports, settings and API documentation no longer require cookies or credentials. New records use the shared LAN actor while existing history retains its recorded actor. Database, broker and provider authentication remain configured independently.

## Restored SSL checker and product/version vulnerability checks

The SSL expiry checker is restored in the sidebar and at `/ssl-checker`, with no login. Domain uploads are processed by a dedicated durable worker; Excel output preserves the supplied script's layout, with safe literal-string cells and a summary sheet. Real DNS queries are bounded, IPs are checked before TLS connections, and expired/untrusted DER certificates are decoded. Seven-day retention covers results while protecting active checks.

Software name/version can now be supplied on upload or corrected by starting a new analysis of a stored file. These values survive resumable upload and are stored per analysis, with the original PE metadata retained as evidence. Automatic extraction also considers FileDescription, fixed product version and FileVersion. Filename candidates remain explicitly uncertain. NVD CPE dictionary lookup extends matching beyond the small catalog; only an unambiguous exact product or product/version mapping is accepted. Findings include a plain-language version conclusion and are shown directly in the analysis page, PDF and JSON reports. The [NVD product API](https://nvd.nist.gov/developers/products) defines the product-dictionary search used here.

Current validation: **241 backend/setup tests passed**, with 10 opt-in PostgreSQL/large-file cases skipped. Three frontend upload tests and TypeScript checks passed; the production build and migration through `0008` completed successfully. Browser verification covered upload with supplied name/version, background processing, review decisions and JSON/PDF downloads. A real provider lookup for the declared test identity `7-Zip 16.00` returned 20 affected advisories; the test executable was a harmless fixture, not a genuine 7-Zip distribution. A second browser check corrected the identity to `Notepad++ 8.1`, resolved its product through the live NVD dictionary, returned 13 affected advisories, downloaded the PDF and preserved the previous report. PE resource extraction was separately checked using a compiled fixture. The live SSL report contained two valid certificates, one expired certificate, one verification failure and one untested wildcard; sorting, filtering, reload and mobile checks passed without browser errors.

Evidence: `.local/verification/tests-features.log`, `browser-export.json`, `browser-export.pdf`, `ssl-browser-status.json`, `ssl-expiry-results.xlsx`, and `name-version-browser-status.json`.

## Earlier private LAN production verification

- `npm start` prepares dependencies, initializes access if needed, applies migrations through `0007`, builds/caches an immutable frontend release, checks services and starts process recovery. No Cuckoo build is attempted while disabled. Unchanged builds are reused; old releases and managed logs are bounded.
- HTTP login, access denial before login, logout revocation, and production mode passed live checks. Automated tests cover password hashing, session revocation/rotation, rate limiting, unavailable Redis, same-origin checks and protected reports/settings.
- Certificate jobs have a dedicated worker and bounded DNS resolution. Analysis and certificate jobs fail explicitly after three interrupted attempts instead of retrying indefinitely. Active work remains protected from retention cleanup.
- The ordinary backend/setup suite passed **238 tests**, with **10 opt-in PostgreSQL/large-file cases skipped**. Five additional release/pruning/HTTP/log/service checks passed. Frontend typecheck and both upload tests passed. The production build completed successfully; the frontend production dependency audit reported no vulnerabilities at the time checked.
- A live domain-list upload produced an Excel file; browser sorting, filtering, reload and mobile layout passed without browser errors. The current run contains valid certificates, a verification failure, a connection reset and an explicitly untested wildcard. Network failures are preserved in output, not replaced with sample results.
- A harmless executable completed static analysis and generated PDF/JSON reports with `COMPLETED_WITH_GAPS` and `REVIEW_REQUIRED`. Live browser settings, history, report download, upload validation and mobile checks passed. The sandbox verification command correctly returned code 2 with `workflow_verified=true`, `sandbox_verified=false`.
- A controlled frontend process termination recovered automatically in **4.0 seconds**, preserving every other service PID. The service now pins the terminal Node installation; both manual startup after service startup and manual startup after recovery reused every service PID.
- The unprivileged systemd user recovery service is installed and enabled. Startup before login and persistence after logout require `sudo loginctl enable-linger "$USER"`; that privileged host setting has not been changed. Native runtime and Compose configuration are separate deployment paths; a full container deployment was not executed.

Current evidence is under `.local/verification/`: `tests-production.log`, `ssl-browser-status.json`, `ssl-expiry-results.xlsx`, `status.json`, `report.pdf`, `report.json`, browser exports, and `production-recovery.json`. These checks establish the tested private LAN behavior, not public hosting readiness or successful guest execution.

## Earlier SSL checker and presentation verification

- The sidebar SSL checker accepts a domain-list text upload, persists a durable background check, displays progress and sortable/filterable results, and downloads the supplied script's nine-column Excel layout plus a summary sheet. The original standalone script is preserved. The adapter decodes untrusted DER certificates so expired and self-signed certificates retain expiry details. Wildcards and connection failures remain explicit result rows.
- Inputs are bounded to 500 unique domains and 256 KiB. DNS results must be public addresses, and connections use the checked IP with the original hostname for SNI. Workbook text is stored as literal strings, including certificate-supplied formula-like values. Text uploads are discarded after parsing; DB results expire after 168 hours, while active checks remain protected. Excel exports are generated in memory.
- Live browser upload, worker processing, Excel download, sorting, filtering, reload and desktop/mobile layout checks passed. Real checks returned valid certificates for example.org/python.org, an expired certificate for expired.badssl.com, and an untrusted certificate for self-signed.badssl.com. A later run encountered a connection reset for the latter and correctly preserved that failure in the report. No live results were fabricated.
- The complete ordinary backend/setup suite passed **227 tests**, with **10 opt-in PostgreSQL/large-file cases skipped**. After three additional SSL error/limit regressions and small follow-up fixes, the focused SSL/setup suite passed **45 tests**. The updated production frontend build passed. Real local TLS fixtures cover trusted, expiring, expired and self-signed certificates.
- A new live executable analysis completed without Cuckoo, produced JSON and PDF reports, retained its seven-day expiration, and required review because of missing evidence. The existing sandbox-verification tool returned code 2 as designed: its evidence records `workflow_verified=true`, `sandbox_verified=false`.
- Startup now prepares changed application dependencies automatically (including openpyxl), applies the SSL migration, and drains/restarts application services when backend code or runtime mode changes. `npm run setup` passes the already-prepared flag when launching the application to avoid reacquiring its own setup lock.

Evidence: `.local/verification/ssl-browser-status.json`, `ssl-expiry-results.xlsx`, `ssl-checker-desktop.png`, `ssl-checker-mobile.png`, `status.json`, `report.json`, and `report.pdf`. The presentation command, example domain list and usage are documented in the repository README.

## Implemented

- `npm run setup` orchestrates dependency checks, pinned Cuckoo/VMCloak installation, reusable ISO download, isolated host provisioning, guest creation, restoration verification and application smoke verification. `npm start` applies migrations, reuses owned processes and starts the application, workers and retention scheduler. Sandbox readiness is required only with `SANDBOX_ENABLED=true` and `CUCKOO_REQUIRED=true`; disabled sandbox operation is supported independently.
- Resumable uploads accept exactly 2 GiB, check every chunk, verify assembled file hashes, retry safely, and preserve file data on disk during worker/provider submission. The UI shows progress, speed, pause/resume and the one-hour inactive-upload expiry.
- Seven-day cleanup removes history, associated database metadata, samples, JSON/PDF reports and owned artifact directories. Shared samples and running analyses remain protected. PostgreSQL locks serialize cleaners across instances. Full sweeps run daily, temporary sweeps hourly and expiration checks every minute. Failure retains inventory for retry.
- Recorded remote sandbox tasks are checked for terminal state and matching identity/hash before deletion; deletion is confirmed by another read. Managed local Cuckoo shared binary caches are collected only in an idle maintenance window, with managed API/core writers stopped, all remaining references inventoried, and the API checked after restart. Unknown ownership or unmanaged writers defer cleanup.
- Software identity and published version evidence feed NVD, CVE Program, CISA KEV, GitHub Advisory and OSV lookups. Unknown identity/package mappings and unsupported versions stay uncertain. Vendor and public exploit references retain provenance; no exploit is fetched or executed. Initial verified catalog mapping is 7-Zip; additional product mappings require source-backed catalog entries. Missing metadata is displayed as identification required.
- DNS requests/responses, process lifetimes/tree and network policy are normalized separately. Cuckoo 3 PCAPs and supported screenshots are streamed into the owning job's artifact namespace. Missing telemetry differs from a completed capture with no traffic. The pinned API does not expose raw behavioral API/file/registry event streams; process metadata and signature evidence are preserved with that limitation.
- HTML viewing and generated JSON/PDF reports combine available evidence and source errors. Vulnerability applicability is separate from the malware score and blocks automatic approval when applicable or uncertain.

## Earlier integration checks

| Check | Result |
|---|---|
| Backend and setup tests | **206 passed**, including the opt-in PostgreSQL and large-upload checks; no skipped tests in the final run |
| PostgreSQL migrations/concurrency | Passed against a separate temporary UTF-8 database/schema; existing records preserved, independent cleanup locks and concurrent reanalysis tested |
| Physical large-file uploads | 32, 100, 500, 1,024 and 2,048 MiB finalized and hashes verified in isolated storage; never executed |
| Large-upload memory | Final test process peaked at 175,480 KiB (~171 MiB); no growth as file size increased from 500 MiB through 2 GiB |
| Frontend | Typecheck, production build and two upload/resume tests passed; production dependency audit reported zero vulnerabilities |
| Live browser | Actual resumable upload → persisted processing → history → review decision → JSON/PDF downloads passed without mocked APIs, including mobile overflow checks |
| Live application smoke | Harmless compiled Windows executable stored and processed; partial report generated. Sandbox/behavior/network/DNS explicitly unavailable; approval remains review required |
| Public advisory APIs | NVD, CVE Program, GitHub, OSV and CISA KEV responded. NVD identified CVE-2016-2334 applicability for synthetic 7-Zip 15.14 metadata. OSV returned 12 applicable records for synthetic Jinja2 2.10 package metadata |
| Startup | Authenticated PostgreSQL/Redis, backend health, frontend proxy and both worker queues passed. Repeated startup reused all eight managed PIDs, including under the originally failing uninstalled locale |
| Setup shutdown and firewall regression checks | **26 setup tests passed**. Live idle shutdown completed in 3.08 seconds with a deliberately open database client, leaving no managed services. Actual nftables 1.1.7 rules passed verification in a disposable network namespace; an extra accept rule and a missing table were rejected |
| Local cache maintenance | Managed API quiesce/restart and readiness check passed against the currently empty Cuckoo database; physical ownership/deletion cases tested with isolated fixtures |
| Containers | Compose configuration validates. Full container deployment was not executed |
| Real guest/network/restore | **Unverified**: presentation mode deliberately skips Cuckoo; guest provisioning errors still require a separate repair |

Local evidence files (ignored by Git) are under `.local/verification/`: `tests-final.log`, `intelligence-live.json`, `status.json`, `report.json`, `report.pdf`, `browser-status.json`, and browser exports. Live provider checks use explicitly declared test metadata; they are not evidence of guest execution or findings from a real 7-Zip upload. Contract fixtures likewise do not establish a working live sandbox or remote S3 deployment.

## Optional remaining Cuckoo provisioning

Run this from the repository root in your interactive terminal:

```bash
npm run setup -- --accept-windows-license
```

This uses the existing Windows ISO and your existing authorization to install it. Enter sudo credentials only in the terminal. Setup displays its dedicated bridge/firewall action and preserves other firewall tables. It stops an idle managed application and refuses to interrupt active analyses. It must finish host verification, guest creation, two-boot restoration checking and the real monitored smoke test before the sandbox can be considered verified. Those unexecuted provisioning stages may still reveal host/guest compatibility issues; their logs and failure states are explicit.

After successful provisioning, normal startup is `npm start`. The current static-analysis workflow starts with `npm start` and `SANDBOX_ENABLED=false` while provisioning remains pending. Shared caches on external sandboxes, third-party provider copies, independent backups and clean VM base snapshots require retention in their owning systems.
