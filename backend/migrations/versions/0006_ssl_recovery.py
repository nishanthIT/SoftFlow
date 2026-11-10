"""Bound recovery of SSL tasks after repeated worker termination."""
from alembic import op
import sqlalchemy as sa
revision='0006'
down_revision='0005'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('ssl_checks',sa.Column('attempts',sa.Integer(),nullable=False,server_default='0'))

def downgrade():
    op.drop_column('ssl_checks','attempts')
