"""Opt-in tests against a disposable PostgreSQL schema, never application tables.

RETENTION_TEST_DATABASE_URL must point to an isolated test database.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import timedelta
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app import retention, main
from app.lifecycle import claim_cleanup, storage_guard
from app.models import Base, Job
from app.config import settings
from test_retention import seed, AT

@pytest.fixture
def postgres(tmp_path,monkeypatch):
    url=os.environ.get('RETENTION_TEST_DATABASE_URL')
    if not url: pytest.skip('Set RETENTION_TEST_DATABASE_URL to an isolated PostgreSQL test database')
    schema='retention_test_'+uuid.uuid4().hex
    admin=create_engine(url)
    with admin.begin() as db: db.execute(text('CREATE SCHEMA '+schema))
    engine=create_engine(url,connect_args={'options':'-csearch_path='+schema})
    Base.metadata.create_all(engine)
    session=sessionmaker(engine,expire_on_commit=False)
    for module in (retention,main): monkeypatch.setattr(module,'Session',session)
    monkeypatch.setattr(settings,'storage_backend','filesystem')
    monkeypatch.setattr(settings,'local_storage_path',str(tmp_path/'objects'))
    from app.models import User
    with session.begin() as db: db.add(User(id='actor',username='LAN workspace'))
    yield session
    engine.dispose()
    with admin.begin() as db: db.execute(text('DROP SCHEMA '+schema+' CASCADE'))
    admin.dispose()


def test_database_lock_excludes_independent_instances_and_recovers_on_disconnect(postgres):
    holder=postgres();holder.begin()
    assert claim_cleanup(holder)
    with postgres.begin() as other: assert not claim_cleanup(other)
    # A separate cleanup session must also skip (without relying on the local lock).
    assert retention.cleanup(AT)['skipped']
    holder.close()
    with postgres.begin() as other: assert claim_cleanup(other)


def test_reanalysis_waits_for_deletion_then_returns_404(postgres):
    from fastapi import HTTPException
    identifier,sample,_=seed(postgres)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with postgres.begin() as cleaner:
            storage_guard(cleaner)
            future=pool.submit(main.start, main.Start(sample_id=sample))
            with pytest.raises(TimeoutError): future.result(timeout=.15)
            assert retention.delete_job(cleaner,identifier,AT)
        with pytest.raises(HTTPException) as error: future.result(timeout=5)
        assert error.value.status_code==404


def test_reanalysis_committed_before_cleanup_keeps_shared_upload(postgres):
    from app import storage
    identifier,sample,sha=seed(postgres)
    new=main.start(main.Start(sample_id=sample))['analysis_id']
    result=retention.cleanup(AT)
    assert result['deleted']==1 and result['failed']==0
    with postgres() as db:
        assert db.get(Job,new).status=='QUEUED'
        assert db.get(Job,identifier) is None
    assert storage.get('samples/'+sha)==b'fixture'


def test_expiration_uses_utc_boundary_in_postgres(postgres):
    expired,_,_=seed(postgres)
    recent,_,_=seed(postgres,age=168-1/3600)
    assert retention.cleanup(AT)['deleted']==1
    assert retention.cleanup(AT+timedelta(seconds=1))['deleted']==1


def test_existing_database_migration_preserves_expiration_and_is_repeatable(postgres,monkeypatch):
    from pathlib import Path
    from alembic.config import Config
    from alembic import command
    from app import models
    engine=postgres.kw['bind']
    Base.metadata.drop_all(engine)
    monkeypatch.setattr(models,'engine',engine)
    config=Config()
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config,'0002')
    with engine.begin() as db:
        db.execute(text("INSERT INTO users (id,username,role) VALUES ('actor','LAN workspace','workspace')"))
        db.execute(text("INSERT INTO samples (id,sha256,sha1,md5,filename,size,created_at) VALUES ('old-sample',:sha,:sha1,:md5,'old.exe',8,:created)"),
            {'sha':'a'*64,'sha1':'b'*40,'md5':'c'*32,'created':AT-timedelta(days=8)})
        db.execute(text("INSERT INTO analysis_jobs (id,sample_id,user_id,status,consent,created_at) VALUES (:id,'old-sample','actor','COMPLETED',false,:created)"),
            {'id':str(uuid.uuid4()),'created':AT-timedelta(days=8)})
    command.upgrade(config,'head')
    command.upgrade(config,'head')
    with postgres() as db:
        job=db.query(Job).one()
        assert retention.expires_at(job.created_at)==AT-timedelta(days=1)
        assert job.cleanup_retry_at is None
    assert retention.cleanup(AT)['deleted']==1
