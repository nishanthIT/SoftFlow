"""Preserve optional product/version declarations through upload and processing."""
from alembic import op
import sqlalchemy as sa
revision='0008'
down_revision='0007'
branch_labels=None
depends_on=None

def upgrade():
    for table in ('uploads','analysis_jobs'):
        op.add_column(table,sa.Column('software_identity',sa.JSON(),nullable=False,server_default='{}'))

def downgrade():
    for table in ('uploads','analysis_jobs'):op.drop_column(table,'software_identity')
