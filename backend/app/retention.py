"""Seven-day analysis retention with crash-safe, file-first deletion and retries."""
import logging
import re
import threading
from datetime import timedelta, timezone
from sqlalchemy import String, cast, delete, or_, select
from .models import Session, Job, Sample, Engine, Audit, Maintenance, Upload, UploadChunk, IntelligenceCache, SSLCheck, record_models, now
from .lifecycle import claim_cleanup, storage_guard
from . import storage, sandbox_cleanup

log=logging.getLogger('sentinel.retention')
RETENTION=timedelta(hours=168)
DAILY=timedelta(hours=24)
TEMPORARY=timedelta(hours=1)
FINISHED={'COMPLETED','FAILED','TIMEOUT','TIMED_OUT','UNSUPPORTED','CANCELLED'}
JOB_PREFIXES=('analyses','artifacts','logs','screenshots','extracted','tmp','uploads')
PREFIXES=('samples','reports',*JOB_PREFIXES)
UUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_local_lock=threading.Lock()


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def expires_at(created_at):
    return utc(created_at)+RETENTION


def expiration(job):
    return {'expires_at':expires_at(job.created_at), 'retention_days':7,
            'cleanup_pending':bool(job.cleanup_retry_at)}


def expired_query(at):
    return select(Job.id).where(Job.created_at <= at-RETENTION, Job.status.in_(FINISHED),
        or_(Job.cleanup_retry_at.is_(None), Job.cleanup_retry_at <= at)).order_by(Job.created_at, Job.id)


def delete_job(db, job_id, at):
    storage_guard(db)
    job=db.scalar(select(Job).where(Job.id==job_id).with_for_update())
    if not job or job.status not in FINISHED or expires_at(job.created_at)>at: return False
    if job.cleanup_retry_at and utc(job.cleanup_retry_at)>at: return False
    sample=db.get(Sample, job.sample_id)
    sandbox=db.scalar(select(Engine).where(Engine.analysis_id==job.id, Engine.name=='sandbox'))
    if sandbox and sandbox.data.get('task_id'):
        # An upstream analysis reused by another job remains owned by that job.
        others=db.scalars(select(Engine).where(Engine.name=='sandbox', Engine.analysis_id!=job.id,
            cast(Engine.data['task_id'].as_string(), String)==str(sandbox.data['task_id'])))
        shared=any((e.data.get('provider') or e.data.get('source')) ==
                   (sandbox.data.get('provider') or sandbox.data.get('source')) and
                   e.data.get('endpoint_identity')==sandbox.data.get('endpoint_identity') for e in others)
        if not shared: sandbox_cleanup.delete_analysis(sandbox.data, sample.sha256)
    elif sandbox:
        sandbox_cleanup.delete_analysis(sandbox.data, sample.sha256)
    # Derived names only: never follow arbitrary paths embedded in reports.
    for extension in ('json','pdf','html'):
        storage.delete(f'reports/{job.id}.{extension}')
    storage.delete_prefix(f'reports/{job.id}/')
    for prefix in JOB_PREFIXES: storage.delete_prefix(f'{prefix}/{job.id}/')
    last_reference=not db.scalar(select(Job.id).where(Job.sample_id==sample.id, Job.id!=job.id).limit(1))
    if last_reference: storage.delete('samples/'+sample.sha256)
    # Physical deletion precedes the DB commit. A crash/failure leaves references
    # available for idempotent retry instead of losing the inventory of files.
    for model in (*record_models.values(), Engine):
        db.execute(delete(model).where(model.analysis_id==job.id))
    db.execute(delete(Audit).where(Audit.data['analysis_id'].as_string()==job.id))
    db.delete(job)
    db.flush()
    if last_reference:
        db.execute(delete(Audit).where(Audit.data['sample_id'].as_string()==sample.id))
        db.delete(sample)
    return True


def owner(key):
    prefix, _, tail=key.partition('/')
    if prefix=='samples' and re.fullmatch(r'[0-9a-f]{64}', tail): return 'sample', tail
    if prefix=='reports':
        match=re.match(r'('+UUID+r')(?:\.[a-z0-9]+|/)', tail)
    else:
        match=re.match(r'('+UUID+r')/', tail) if prefix in JOB_PREFIXES else None
    return ('job', match[1]) if match else (None, None)


def sweep_orphans(db, at, *, full, local_cache=False):
    storage_guard(db)
    # Serializes with upload persistence and reanalysis creation across instances.
    # Worker writes belong to RUNNING jobs, which always remain protected.
    for upload in db.scalars(select(Upload).where(Upload.updated_at<=at-TEMPORARY).with_for_update(skip_locked=True)):
        storage.delete_prefix(f'uploads/{upload.id}/')
        db.execute(delete(UploadChunk).where(UploadChunk.upload_id==upload.id));db.delete(upload)
    db.flush()
    prefixes=PREFIXES if full else ('tmp','uploads','samples')
    for prefix in prefixes:
        for key, modified in storage.objects(prefix+'/'):
            if utc(modified)>at-TEMPORARY: continue
            kind, identifier=owner(key)
            if prefix=='uploads' and identifier and db.get(Upload,identifier):continue
            if kind=='sample' and db.scalar(select(Sample.id).where(Sample.sha256==identifier)): continue
            job=db.get(Job, identifier) if kind=='job' else None
            if job:
                # Disposable scratch can go early after a failed/finished job,
                # but reports, screenshots and evidence retain the full 7 days.
                if prefix not in ('tmp','uploads') or job.status not in FINISHED: continue
                if not job.completed_at or utc(job.completed_at)>at-TEMPORARY: continue
                sandbox=db.scalar(select(Engine).where(Engine.analysis_id==job.id, Engine.name=='sandbox'))
                if sandbox and sandbox.data.get('task_id'): continue
            # Unknown names are only disposable atomic-write leftovers or files
            # in explicitly reserved temporary namespaces.
            if not kind and prefix not in ('tmp','uploads') and not key.rsplit('/',1)[-1].startswith('.tmp-'): continue
            storage.delete(key)
    # DB-only samples left by an upload that failed before job creation.
    for sample in db.scalars(select(Sample).where(Sample.created_at<=at-TEMPORARY,
            ~select(Job.id).where(Job.sample_id==Sample.id).exists())):
        storage.delete('samples/'+sample.sha256)
        db.execute(delete(Audit).where(Audit.data['sample_id'].as_string()==sample.id))
        db.delete(sample)
    def protected_upload(key):
        kind, identifier=owner(key)
        return kind=='job' and (db.get(Job,identifier) is not None or db.get(Upload,identifier) is not None)
    storage.abort_abandoned_uploads(at-TEMPORARY, protected_upload)
    if full:
        db.execute(delete(IntelligenceCache).where(IntelligenceCache.expires_at<=at))
        db.execute(delete(Audit).where(Audit.created_at<=at-RETENTION,
            or_(Audit.data['analysis_id'].as_string().is_(None),
                ~Audit.data['analysis_id'].as_string().in_(select(Job.id)))))
        # The local Cuckoo API does not collect shared binaries. Quiesce its
        # managed writers only when no application analysis can be using them.
        # External installations own this host-level cache maintenance.
        from .config import settings
        if local_cache and settings.cuckoo_auto_start and not db.scalar(select(Job.id).where(Job.status.not_in(FINISHED)).limit(1)):
            import subprocess,sys
            from pathlib import Path
            root=Path(__file__).resolve().parents[2]
            subprocess.run([sys.executable,str(root/'scripts/local.py'),'cache-gc'],cwd=root,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=90)


def cleanup(at=None, *, local_cache=False):
    at=utc(at or now())
    stats={'deleted':0, 'failed':0, 'skipped':False}
    # Also serializes SQLite tests and threads; the PostgreSQL transaction lock
    # below is the authority across worker processes, hosts and beat replicas.
    if not _local_lock.acquire(blocking=False): return {**stats,'skipped':True}
    try:
        with Session.begin() as coordinator:
            if not claim_cleanup(coordinator): return {**stats,'skipped':True}
            state=coordinator.get(Maintenance, 'retention')
            if not state:
                state=Maintenance(name='retention'); coordinator.add(state)
            full=not state.last_full_at or utc(state.last_full_at)<=at-DAILY
            temporary=full or not state.last_temporary_at or utc(state.last_temporary_at)<=at-TEMPORARY
            # Domain uploads are discarded after parsing; DB results expire here.
            # Active certificate workers remain protected until completion.
            with Session.begin() as db:
                db.execute(delete(SSLCheck).where(SSLCheck.created_at<=at-RETENTION,
                    SSLCheck.status.in_(['COMPLETED','FAILED'])))
            with Session() as db: ids=list(db.scalars(expired_query(at)))
            for identifier in ids:
                try:
                    with Session.begin() as db:
                        removed=delete_job(db, identifier, at)
                    if removed: stats['deleted']+=1
                except Exception as error:
                    stats['failed']+=1
                    # Log identifiers/types only: provider exceptions can contain secrets.
                    log.error('retention_job_failed analysis_id=%s error=%s retry_in_hours=24', identifier, type(error).__name__)
                    with Session.begin() as db:
                        job=db.get(Job, identifier)
                        if job:
                            job.cleanup_retry_at=at+DAILY
                            job.cleanup_error=type(error).__name__
            if temporary:
                try:
                    with Session.begin() as db: sweep_orphans(db, at, full=full, local_cache=local_cache)
                except Exception as error:
                    stats['failed']+=1
                    log.error('retention_sweep_failed error=%s', type(error).__name__)
                # Failed sweeps retry at their next scheduled interval. Job
                # retries remain independent and survive scheduler restarts.
                state.last_temporary_at=at
                if full: state.last_full_at=at
        if stats['deleted'] or stats['failed'] or temporary:
            log.warning('retention_cleanup %s', stats)
        return stats
    finally: _local_lock.release()
