# Analysis workers

The worker implementation is `backend/app/tasks.py`; workers share the backend image and database schema. Run `celery -A app.tasks worker --concurrency=2` with a separate Celery beat process.

PostgreSQL jobs are the durable dispatch outbox. Beat retries dispatch every 15 seconds. Redis leases prevent concurrent execution of the same analysis. Completed stages survive worker restarts; sandbox task IDs are checkpointed before polling. A worker crash after a remote submission but before persistence can duplicate that external submission (providers do not offer a universal idempotency contract). Never run multiple beat processes. Provider errors are terminal per engine and do not prevent remaining engines from running.

The worker only parses samples or transmits them to configured APIs. It never invokes an uploaded executable. Worker resource limits constrain hostile parsers. For higher assurance, move static/YARA parsing to separate disposable, credential-free containers behind a constrained job API.
