"""Bound repeated recovery of terminated analysis workers."""
from alembic import op
import sqlalchemy as sa
revision='0007'
down_revision='0006'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('analysis_jobs',sa.Column('attempts',sa.Integer(),nullable=False,server_default='0'))

def downgrade():
    op.drop_column('analysis_jobs','attempts')
