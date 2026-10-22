"""Preserve the filename on each submission, including duplicate content."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('analysis_jobs', sa.Column('submitted_filename', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('analysis_jobs', 'submitted_filename')
