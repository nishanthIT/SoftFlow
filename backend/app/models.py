import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Integer, BigInteger, Boolean, JSON, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings

def now(): return datetime.now(timezone.utc)
def uid(): return str(uuid.uuid4())
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    role: Mapped[str] = mapped_column(String(20), default='admin')
class Sample(Base):
    __tablename__ = 'samples'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
class Job(Base):
    __tablename__ = 'analysis_jobs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    sample_id: Mapped[str] = mapped_column(ForeignKey('samples.id'), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(20), default='QUEUED', index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consent: Mapped[bool] = mapped_column(Boolean, default=False)
    submitted_filename: Mapped[str | None] = mapped_column(String(255))
    software_identity: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleanup_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleanup_error: Mapped[str | None] = mapped_column(String(100))
class Maintenance(Base):
    __tablename__ = 'maintenance_state'
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    last_full_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_temporary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
class Upload(Base):
    __tablename__ = 'uploads'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(BigInteger)
    received: Mapped[int] = mapped_column(BigInteger, default=0)
    consent: Mapped[bool] = mapped_column(Boolean, default=False)
    software_identity: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(20), default='OPEN')
    analysis_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
class UploadChunk(Base):
    __tablename__ = 'upload_chunks'
    upload_id: Mapped[str] = mapped_column(ForeignKey('uploads.id'), primary_key=True)
    offset: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
class IntelligenceCache(Base):
    __tablename__ = 'intelligence_cache'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
class SSLCheck(Base):
    """Durable certificate checks with seven-day retention."""
    __tablename__ = 'ssl_checks'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    filename: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default='QUEUED', index=True)
    domains: Mapped[list] = mapped_column(JSON)
    results: Mapped[list] = mapped_column(JSON, default=list)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
class Engine(Base):
    __tablename__ = 'analysis_engine_results'
    __table_args__ = (UniqueConstraint('analysis_id','name'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    analysis_id: Mapped[str] = mapped_column(ForeignKey('analysis_jobs.id'), index=True)
    name: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default='QUEUED')
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    reason: Mapped[str | None] = mapped_column(String(1000))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(100))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
# Source-preserving normalized records. JSON payload schemas are versioned by pipeline policy.
record_models = {}
for table in ['static_results','sandbox_results','network_events','yara_matches','ai_indicators','behavior_events','iocs','verdicts','analyst_reviews']:
    record_models[table] = type(''.join(x.title() for x in table.split('_')), (Base,), {
        '__tablename__': table,
        'id': mapped_column(String(36), primary_key=True, default=uid),
        'analysis_id': mapped_column(ForeignKey('analysis_jobs.id'), index=True),
        'data': mapped_column(JSON, nullable=False),
        'created_at': mapped_column(DateTime(timezone=True), default=now),
    })
engine = create_engine(settings.database_url, pool_pre_ping=True)
Session = sessionmaker(engine, expire_on_commit=False)
ENGINES = ['validation','hashing','static','yara','vulnerabilities','virustotal','hybrid-analysis','sandbox','behavior','network','dns','ai','correlation','verdict','report']
TERMINAL = {'COMPLETED','FAILED','TIMEOUT','UNAVAILABLE','SKIPPED'}
