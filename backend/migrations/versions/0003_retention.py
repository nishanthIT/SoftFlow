"""Durable cleanup retries and scheduler state; existing jobs keep their creation time."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('analysis_jobs', sa.Column('cleanup_retry_at', sa.DateTime(timezone=True)))
    op.add_column('analysis_jobs', sa.Column('cleanup_error', sa.String(100)))
    op.create_index('ix_analysis_jobs_created_at', 'analysis_jobs', ['created_at'])
    op.create_table('maintenance_state',
        sa.Column('name', sa.String(40), primary_key=True),
        sa.Column('last_full_at', sa.DateTime(timezone=True)),
        sa.Column('last_temporary_at', sa.DateTime(timezone=True)))


def downgrade():
    op.drop_table('maintenance_state')
    op.drop_index('ix_analysis_jobs_created_at', table_name='analysis_jobs')
    op.drop_column('analysis_jobs', 'cleanup_error')
    op.drop_column('analysis_jobs', 'cleanup_retry_at')
