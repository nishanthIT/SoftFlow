"""Real file deletion and relational cleanup; all data belongs to temporary fixtures."""
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine, event, select, func
from sqlalchemy.orm import sessionmaker
from app import retention, storage, main, tasks
from app.config import settings
from app.models import Base, User, Sample, Job, Engine, Audit, Maintenance, record_models

AT=datetime(2026, 11, 8, 12, tzinfo=timezone.utc)

@pytest.fixture
def store(tmp_path, monkeypatch):
    engine=create_engine('sqlite:///'+str(tmp_path/'db.sqlite'))
    @event.listens_for(engine, 'connect')
    def foreign_keys(connection, _): connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    session=sessionmaker(engine, expire_on_commit=False)
    for module in (retention, main, tasks): monkeypatch.setattr(module, 'Session', session)
    monkeypatch.setattr(settings, 'storage_backend', 'filesystem')
    monkeypatch.setattr(settings, 'local_storage_path', str(tmp_path/'objects'))
    with session.begin() as db: db.add(User(id='actor', username='LAN workspace'))
    yield session
    engine.dispose()


def artifact(key, age=8*24):
    storage.put(key, b'fixture')
    modified=(AT-timedelta(hours=age)).timestamp()
    os.utime(storage.local_path(key), (modified,modified))
    return storage.local_path(key)


def seed(session, *, age=168, status='COMPLETED', sample_id=None, completed_age=None):
    identifier=str(uuid.uuid4())
    created=AT-timedelta(hours=age)
    with session.begin() as db:
        sample=db.get(Sample, sample_id) if sample_id else Sample(
            sha256=uuid.uuid4().hex*2, sha1='1'*40, md5='1'*32,
            filename='fixture.exe', size=7, created_at=created)
        if not sample_id: db.add(sample); db.flush()
        job=Job(id=identifier, sample_id=sample.id, user_id='actor', status=status,
                created_at=created, completed_at=AT-timedelta(hours=completed_age if completed_age is not None else max(0,age-1)))
        db.add(job); db.flush()
        db.add(Engine(analysis_id=identifier, name='sandbox', status='UNAVAILABLE', data={}))
        for model in record_models.values(): db.add(model(analysis_id=identifier, data={'fixture':True}))
        db.add(Audit(action='analysis.created', data={'analysis_id':identifier, 'sample_id':sample.id}, created_at=created))
        # Even a new audit entry must disappear with its expired analysis.
        db.add(Audit(action='analysis.decision', data={'analysis_id':identifier}, created_at=AT))
        sample_id=sample.id; sha=sample.sha256
    artifact('samples/'+sha, age)
    for key in (f'reports/{identifier}.json', f'reports/{identifier}.pdf', f'reports/{identifier}.html',
                f'reports/{identifier}/extra.json', f'artifacts/{identifier}/nested/memory.dmp',
                f'logs/{identifier}/sandbox.log', f'screenshots/{identifier}/screen.png',
                f'extracted/{identifier}/unpacked.bin', f'analyses/{identifier}/data.bin',
                f'tmp/{identifier}/partial', f'uploads/{identifier}/part'):
        artifact(key,age)
    return identifier,sample_id,sha


def test_full_physical_and_database_cleanup_at_exact_boundary(store):
    expired,sample,sha=seed(store)
    recent,_,_=seed(store, age=168-1/3600)
    active,_,_=seed(store, age=500, status='RUNNING')
    queued,_,_=seed(store, age=500, status='QUEUED')
    result=retention.cleanup(AT)
    assert result=={'deleted':1, 'failed':0, 'skipped':False}
    with store() as db:
        assert db.get(Job, expired) is None and db.get(Sample,sample) is None
        for model in (*record_models.values(),Engine):
            assert not db.scalar(select(model.id).where(model.analysis_id==expired))
        assert not db.scalar(select(Audit.id).where(Audit.data['analysis_id'].as_string()==expired))
        assert all(db.get(Job,id) for id in (recent,active,queued))
    keys=[str(p.relative_to(settings.local_storage_path)) for p in Path(settings.local_storage_path).rglob('*') if p.is_file()]
    assert all(expired not in key and sha not in key for key in keys)
    assert storage.get(f'reports/{active}.json')==b'fixture'
    assert storage.get(f'tmp/{active}/partial')==b'fixture'
    assert retention.cleanup(AT)['deleted']==0


def test_shared_upload_survives_until_last_reference_expires(store):
    old,sample,sha=seed(store, age=200)
    new,_,_=seed(store,age=1,sample_id=sample)
    assert retention.cleanup(AT)['deleted']==1
    assert storage.get('samples/'+sha)==b'fixture'
    with store() as db: assert db.get(Sample,sample) and db.get(Job,new)
    assert retention.cleanup(AT+timedelta(days=7))['deleted']==1
    assert not storage.local_path('samples/'+sha).exists()


def test_partial_delete_failure_keeps_inventory_and_retries_next_day(store,monkeypatch,caplog):
    identifier,sample,sha=seed(store, age=200)
    other,_,_=seed(store,age=200)
    real_delete=storage.delete
    def fail(key):
        if key==f'reports/{identifier}.pdf': raise OSError('private token must not be logged')
        real_delete(key)
    monkeypatch.setattr(storage,'delete',fail)
    result=retention.cleanup(AT)
    assert result['failed']==1 and result['deleted']==1
    assert not storage.local_path(f'reports/{identifier}.json').exists()
    assert storage.local_path(f'reports/{identifier}.pdf').exists()
    with store() as db:
        assert db.get(Sample,sample)
        job=db.get(Job,identifier)
        assert retention.utc(job.cleanup_retry_at)==AT+timedelta(days=1)
        assert job.cleanup_error=='OSError'
        assert db.get(Job,other) is None
    assert 'private token' not in caplog.text
    monkeypatch.setattr(storage,'delete',real_delete)
    assert retention.cleanup(AT+timedelta(hours=23))['deleted']==0
    assert retention.cleanup(AT+timedelta(hours=24))['deleted']==1
    assert not storage.local_path('samples/'+sha).exists()


def test_temporary_orphan_cleanup_and_active_protection(store):
    failed,_,_=seed(store, age=3, status='FAILED')
    active,_,_=seed(store, age=200, status='RUNNING')
    orphan=artifact('uploads/'+str(uuid.uuid4())+'/abandoned',age=2)
    recent=artifact('uploads/'+str(uuid.uuid4())+'/new',age=.5)
    unknown=artifact('artifacts/unrelated/keep',age=200)
    old_report=artifact('reports/'+str(uuid.uuid4())+'.json',age=2)
    old_atomic=artifact('samples/.tmp-abandoned',age=2)
    fresh_atomic=artifact('samples/.tmp-writing',age=.5)
    assert retention.cleanup(AT)['failed']==0
    assert not orphan.exists() and not old_report.exists() and not old_atomic.exists()
    assert recent.exists() and unknown.exists() and fresh_atomic.exists()
    assert not storage.local_path(f'tmp/{failed}/partial').exists()
    assert storage.local_path(f'reports/{failed}.json').exists()
    assert storage.local_path(f'tmp/{active}/partial').exists()
    with store() as db: assert db.get(Job,failed) and db.get(Job,active)


def test_database_only_abandoned_sample_and_hourly_sweep(store):
    with store.begin() as db:
        db.add(Sample(id='abandoned',sha256='a'*64,sha1='b'*40,md5='c'*32,
            filename='broken.exe',size=8,created_at=AT-timedelta(hours=2)))
    artifact('samples/'+'a'*64,age=2)
    assert retention.cleanup(AT)['failed']==0
    with store() as db: assert db.get(Sample,'abandoned') is None
    orphan=artifact('tmp/'+str(uuid.uuid4())+'/part',age=2)
    retention.cleanup(AT+timedelta(minutes=59)); assert orphan.exists()
    retention.cleanup(AT+timedelta(hours=1)); assert not orphan.exists()


def test_singleton_lock_denial_does_not_touch_data(store,monkeypatch):
    identifier,_,_=seed(store)
    monkeypatch.setattr(retention,'claim_cleanup',lambda db:False)
    assert retention.cleanup(AT)['skipped']
    assert storage.local_path(f'reports/{identifier}.json').exists()
    with store() as db: assert db.get(Maintenance,'retention') is None


def test_running_sandbox_protects_locally_finished_analysis(store,monkeypatch):
    identifier,_,_=seed(store)
    with store.begin() as db:
        engine=db.scalar(select(Engine).where(Engine.analysis_id==identifier))
        engine.data={'task_id':'20261101-ABCDEF','provider':'cuckoo3'}
    def active(*args): raise retention.sandbox_cleanup.SandboxStillActive()
    monkeypatch.setattr(retention.sandbox_cleanup,'delete_analysis',active)
    assert retention.cleanup(AT)['failed']==1
    assert storage.local_path(f'reports/{identifier}.json').exists()
    assert storage.local_path(f'tmp/{identifier}/partial').exists()


def test_api_history_expiration_is_creation_plus_168_hours(store):
    identifier,sample,_=seed(store,age=2)
    result=main.analysis_data(identifier)
    assert result['expires_at']==AT+timedelta(hours=166)
    assert main.sample(sample)['analyses'][0]['expires_at']==result['expires_at']
    assert main.samples()[0]['expires_at']==result['expires_at']
    assert result['retention_days']==7


def test_scheduler_registers_daily_and_expiration_jobs():
    entries=tasks.celery.conf.beat_schedule
    assert entries['retention-daily']['schedule']==86400
    assert entries['retention-expiration-check']['schedule']==60
    assert tasks.cleanup.ignore_result


def test_storage_paths_cannot_escape_or_follow_symlinks(store,tmp_path):
    for key in ('../outside','/absolute','samples/../bad','samples\\bad',''):
        with pytest.raises(ValueError): storage.delete(key)
    outside=tmp_path/'outside';outside.write_bytes(b'keep')
    root=Path(settings.local_storage_path);root.mkdir()
    (root/'samples').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError): storage.delete('samples/outside')
    assert outside.read_bytes()==b'keep'


def test_atomic_writer_lock_prevents_deletion(store):
    import fcntl
    path=artifact('samples/.tmp-busy',age=2)
    with path.open('rb') as writer:
        fcntl.flock(writer, fcntl.LOCK_EX)
        with pytest.raises(RuntimeError): storage.delete('samples/.tmp-busy')
        assert path.exists()
    storage.delete('samples/.tmp-busy')
    assert not path.exists()


def test_shared_remote_task_is_deleted_only_for_last_owner(store,monkeypatch):
    old,sample,_=seed(store,age=200)
    new,_,_=seed(store,age=2,sample_id=sample)
    with store.begin() as db:
        for e in db.scalars(select(Engine)):
            e.data={'task_id':42,'source':'cape'}
    calls=[]
    monkeypatch.setattr(retention.sandbox_cleanup,'delete_analysis',lambda *args:calls.append(args))
    assert retention.cleanup(AT)['deleted']==1
    assert not calls
    assert retention.cleanup(AT+timedelta(days=7))['deleted']==1
    assert len(calls)==1


def test_symlink_in_artifact_tree_keeps_inventory_and_external_file(store,tmp_path):
    identifier,_,_=seed(store)
    outside=tmp_path/'outside.bin';outside.write_bytes(b'keep')
    path=storage.local_path(f'artifacts/{identifier}/link')
    path.symlink_to(outside)
    assert retention.cleanup(AT)['failed']>=1
    with store() as db: assert db.get(Job,identifier)
    assert outside.read_bytes()==b'keep'


def test_artifact_inventory_errors_do_not_drop_database_references(store,monkeypatch):
    identifier,_,_=seed(store)
    real_walk=storage.os.walk
    def unreadable(path,**kwargs):
        if str(path).endswith('artifacts/'+identifier):
            kwargs['onerror'](PermissionError('unreadable fixture'))
        return real_walk(path,**kwargs)
    monkeypatch.setattr(storage.os,'walk',unreadable)
    assert retention.cleanup(AT)['failed']>=1
    with store() as db: assert db.get(Job,identifier)


def test_database_commit_failure_retries_after_files_are_already_gone(store):
    identifier,_,sha=seed(store)
    failed=False
    @event.listens_for(store.class_, 'before_commit')
    def fail_once(db):
        nonlocal failed
        if not failed and any(isinstance(row,Sample) for row in db.deleted):
            failed=True
            raise RuntimeError('fixture commit loss')
    result=retention.cleanup(AT)
    assert result['deleted']==0 and result['failed']==1
    assert not storage.local_path('samples/'+sha).exists()
    with store() as db: assert db.get(Job,identifier)
    assert retention.cleanup(AT+timedelta(days=1))['deleted']==1


def test_legacy_certificate_records_still_expire_without_the_removed_feature(store):
    from app.models import SSLCheck
    cases=[('expired','COMPLETED',168),('failed','FAILED',169),('recent','COMPLETED',167),('active','RUNNING',200)]
    with store.begin() as db:
        for identifier,status,hours in cases:
            db.add(SSLCheck(id=identifier,filename='legacy.txt',status=status,domains=['example.org'],results=[],created_at=AT-timedelta(hours=hours)))
    assert retention.cleanup(AT)['failed']==0
    with store() as db:
        assert set(db.scalars(select(SSLCheck.id)))=={'recent','active'}
