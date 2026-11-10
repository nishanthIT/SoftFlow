"""Resumable 2 GiB uploads and expiring public intelligence cache."""
from alembic import op
import sqlalchemy as sa
revision='0004'
down_revision='0003'
branch_labels=None
depends_on=None

def upgrade():
    op.alter_column('samples','size',existing_type=sa.Integer(),type_=sa.BigInteger())
    op.create_table('uploads',
        sa.Column('id',sa.String(36),primary_key=True), sa.Column('filename',sa.String(255),nullable=False),
        sa.Column('size',sa.BigInteger(),nullable=False), sa.Column('received',sa.BigInteger(),nullable=False),
        sa.Column('consent',sa.Boolean(),nullable=False), sa.Column('state',sa.String(20),nullable=False),
        sa.Column('analysis_id',sa.String(36)), sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('updated_at',sa.DateTime(timezone=True),nullable=False))
    op.create_index('ix_uploads_updated_at','uploads',['updated_at'])
    op.create_table('upload_chunks',sa.Column('upload_id',sa.String(36),sa.ForeignKey('uploads.id'),primary_key=True),
        sa.Column('offset',sa.BigInteger(),primary_key=True),sa.Column('size',sa.Integer(),nullable=False),
        sa.Column('sha256',sa.String(64),nullable=False))
    op.create_table('intelligence_cache',sa.Column('key',sa.String(64),primary_key=True),
        sa.Column('data',sa.JSON(),nullable=False),sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False))
    op.create_index('ix_intelligence_cache_expires_at','intelligence_cache',['expires_at'])

def downgrade():
    op.drop_table('intelligence_cache');op.drop_table('upload_chunks');op.drop_table('uploads')
    # Keep BigInteger: narrowing could corrupt already uploaded 2 GiB samples.
