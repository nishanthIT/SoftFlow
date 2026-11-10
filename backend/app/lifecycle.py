"""Database locks shared by storage writers and retention (PostgreSQL in production)."""
from sqlalchemy import text

# Transaction-scoped advisory locks cannot expire while a live cleaner is deleting.
CLEANUP_LOCK = 7142938101
STORAGE_LOCK = 7142938102


def storage_guard(db, *, shared=False):
    if db.get_bind().dialect.name == 'postgresql':
        function = 'pg_advisory_xact_lock_shared' if shared else 'pg_advisory_xact_lock'
        db.execute(text(f'SELECT {function}(:key)'), {'key': STORAGE_LOCK})


def claim_cleanup(db):
    if db.get_bind().dialect.name == 'postgresql':
        return db.scalar(text('SELECT pg_try_advisory_xact_lock(:key)'), {'key': CLEANUP_LOCK})
    # SQLite is used only by isolated unit tests; production uses PostgreSQL.
    return True
