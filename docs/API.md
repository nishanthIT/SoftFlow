# API and events

All application endpoints are available without login, cookies, or bearer tokens. Provider credentials are separate and stay on the server. OpenAPI: `/api/docs`, schema: `/api/openapi.json`. Access through the frontend's LAN port.

- `POST /api/samples`: multipart `file` and optional `external_consent`; returns analysis/sample IDs, hashes, and duplicate status. Jobs are committed before the response and dispatched within approximately 15 seconds.
- `POST /api/analysis`: JSON `sample_id`, optional `external_consent`, to analyze existing stored bytes again.
- `GET /api/analysis/{id}` or `/status`: job, sample, engine states, progress, approval recommendation, criteria and decision history. Job states are `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`. Engine states additionally include `TIMEOUT`, `UNAVAILABLE`, `SKIPPED`. `final_status=COMPLETED_WITH_GAPS` distinguishes partial coverage.
- `GET /api/analysis/{id}/events`: SSE snapshots and heartbeats; reconnect/polling supported.
- `POST /api/analysis/{id}/decision`: JSON `decision` (`APPROVE`, `REJECT`, `REVIEW_REQUIRED`) and nonblank `reason` (maximum 2,000 characters). Appends a review with the current assessment and audit event. Approval is rejected with 409 unless analysis meets acceptance criteria. The actor is explicitly unauthenticated.
- `GET /api/analysis/{id}/report`: JSON attachment containing evidence, step status/errors, recommendation and decision history. 409 while running; 503 if an existing stored report cannot be read. Failed jobs can export partial reports. Analysis evidence remains immutable; the response appends current decisions from PostgreSQL.
- `GET /api/analysis/{id}/{engine}` and `/{engine}/raw`: normalized and available source evidence. Report is reserved for the aggregate report endpoint.
- `GET /api/samples?limit=50&offset=0`, `/api/samples/{id}`: samples and analysis history.
- `GET /api/settings`, `/api/rules`, `/api/admin`, `/api/providers/health`: configuration without secrets, rules, operations/audits, live provider/worker diagnostics.
- `GET /health`: database, Redis and storage connectivity; 503 when unhealthy.

Foreign-origin browser mutations are rejected. Same-origin LAN proxy writes work without a hostname allowlist. Unsupported files return 422 and oversize uploads 413. ISO timestamps use UTC. No uploaded-binary download endpoint exists. No application authentication routes remain.
