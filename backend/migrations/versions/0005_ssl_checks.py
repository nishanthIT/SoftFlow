"""Independent SSL certificate checks with seven-day retention."""
from alembic import op
import sqlalchemy as sa
revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('ssl_checks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('domains', sa.JSON(), nullable=False),
        sa.Column('results', sa.JSON(), nullable=False),
        sa.Column('error', sa.String(1000)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True)))
    op.create_index('ix_ssl_checks_status', 'ssl_checks', ['status'])
    op.create_index('ix_ssl_checks_created_at', 'ssl_checks', ['created_at'])

def downgrade():
    op.drop_table('ssl_checks')
