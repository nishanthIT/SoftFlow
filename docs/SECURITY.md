# Security model and deployment boundary

All samples are hostile. The application never launches uploaded bytes. Private object keys use SHA-256, never user filenames; samples cannot be downloaded through this API. Upload validation bounds memory and checks DOS/PE headers before durable storage. Static parsers run as a non-root user with capability drops, no writable root filesystem and resource limits. PE parsing and YARA are native attack surfaces; harden further with isolated per-file parser workers before exposing this platform to adversarial public users.

Application authentication is intentionally absent. Anyone with network access to the frontend can read workspace data, submit files and record decisions. Same-origin browser mutation checks remain, but are not authentication. New audit records use a shared LAN actor; historical user foreign keys remain intact. Deployment is for a trusted LAN, with only the frontend published. The sandbox guest network must be isolated from the application LAN.

Secrets stay in the backend environment. Protect `.env` with mode 600. No API returns key values. Rotate provider and infrastructure credentials on compromise. Redis and PostgreSQL are authenticated and internal-only. The sample bucket blocks public access. Use a dedicated least-privilege S3 identity for normal workers in production; root MinIO credentials in Compose are bootstrap convenience, not the recommended production credential model.

External hash lookups disclose hashes. File bytes are transmitted externally only with both administrator enablement and job-specific consent. Public provider submissions may be shared with vendors and researchers. Do not share confidential executables without organizational authorization.

Verdict policy version 1.1 is deterministic, conservative and deliberately limited: VT malicious counts, explicit Hybrid Analysis verdicts, YARA matches observed high-severity behavior, and native Cuckoo 3 scores drive its score. AI signatures are never part of that score. The application does not claim certificate-chain or Authenticode verification; it displays certificate presence and parsed metadata separately from trust. Missing network telemetry produces UNAVAILABLE and an inconclusive negative AI result. Historic provider reports may be stale; timestamps are retained where present.

Operational controls required: HTTPS termination, network segmentation, private administrative access, OS/container patching, backups and tested recovery, storage encryption and retention, supply-chain scanning, monitoring of failed stages and worker heartbeats, sandbox restore auditing, provider account limits, and independent penetration testing. The code and local tests do not certify those deployment controls.

Approval is a separate assessment with captured criteria, reasons, coverage and limitations. Missing/failed execution never qualifies for approval. This application does not perform vulnerability scanning.
