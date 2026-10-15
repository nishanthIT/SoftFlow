# REST and events

Interactive OpenAPI is served by FastAPI at `/docs` (proxied at `/api/docs`); schema at `/openapi.json`.

1. `POST /api/auth/login` with JSON `{ "username": "admin", "password": "…" }`; retain the HTTP-only cookie.
2. `POST /api/samples` multipart fields `file` and `external_consent`. Returns `analysis_id`, `sample_id`, hashes and a duplicate indicator. A job and engine rows are committed before response. Background dispatch starts within 15 seconds.
3. `GET /api/analysis/{id}` or `/status` returns persisted sample, job and engine records. Status is QUEUED, RUNNING or terminal. Progress measures terminal stages, including failed/unavailable states.
4. `GET /api/analysis/{id}/events` returns SSE JSON snapshots with heartbeats. Clients can reconnect and receive the complete current state; no event replay cursor is necessary. Polling is also supported.
5. `GET /api/analysis/{id}/report` returns the final or partial report JSON. Every engine's status and reason accompanies evidence.
6. `GET /api/analysis/{id}/{engine}` supports `virustotal`, `hybrid-analysis`, `sandbox`, `static`, `yara`, `behavior`, `network`, `ai`, `correlation`, `verdict`, `report` (report is the aggregate route).
7. `GET /api/samples?limit=50&offset=0`; `GET /api/samples/{id}` includes analysis history. `POST /api/analysis` starts a new job for an existing sample with `sample_id` and `external_consent`.
8. `GET /api/settings`, `/api/rules`, `/api/admin`, `/health/providers` require authentication. `/health` exposes dependency connectivity only and returns 503 when unhealthy.

All workspace data is administrative in this single-admin release. ISO timestamps use UTC. Failed external calls return engine errors without credentials or raw HTTP URLs. Uploads above limit return 413; malformed files return 422. IDs are opaque UUID strings. No binary sample download endpoint exists.
