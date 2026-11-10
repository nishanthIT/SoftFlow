import boto3
import os
import tempfile
import fcntl
import errno
from datetime import datetime, timezone
from pathlib import Path
from botocore.config import Config
from .config import settings

def client():
    return boto3.client('s3', endpoint_url=settings.minio_endpoint, aws_access_key_id=settings.minio_access_key,
                       aws_secret_access_key=settings.minio_secret_key, config=Config(signature_version='s3v4', retries={'max_attempts': 3}))
def put(key, data, content_type='application/octet-stream'):
    if settings.storage_backend == 'filesystem':
        path = local_path(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
                os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        return
    client().put_object(Bucket=settings.storage_bucket, Key=key, Body=data, ContentType=content_type)
def get(key, *, max_bytes=None):
    if settings.storage_backend == 'filesystem':
        with local_path(key).open('rb') as f:
            data=f.read() if max_bytes is None else f.read(max_bytes+1)
        if max_bytes is not None and len(data)>max_bytes:raise ValueError('Storage object exceeds the expected byte limit')
        return data
    response = client().get_object(Bucket=settings.storage_bucket, Key=key)
    try:
        data=response['Body'].read() if max_bytes is None else response['Body'].read(max_bytes+1)
        if max_bytes is not None and len(data)>max_bytes:raise ValueError('Storage object exceeds the expected byte limit')
        return data
    finally: response['Body'].close()


def local_path(key):
    root=Path(settings.local_storage_path).resolve()
    parts=key.split('/')
    if not key or any(part in ('', '.', '..') for part in parts) or '\\' in key:
        raise ValueError('Invalid storage object key')
    target=root
    for part in parts:
        target=target/part
        if target.is_symlink(): raise ValueError('Symlinks are not storage objects')
    return target


def objects(prefix):
    """Stream managed objects, including old S3 versions and delete markers."""
    if settings.storage_backend == 'filesystem':
        root=Path(settings.local_storage_path).resolve()
        base=local_path(prefix.rstrip('/'))
        if not base.exists(): return
        def walk_error(error): raise error
        for directory, dirs, files in os.walk(base, followlinks=False, onerror=walk_error):
            if any((Path(directory)/name).is_symlink() for name in dirs+files):
                raise ValueError('Symlinks found in managed storage')
            for name in files:
                path=Path(directory)/name
                try: modified=path.stat().st_mtime
                except FileNotFoundError: continue
                yield str(path.relative_to(root)), datetime.fromtimestamp(modified, timezone.utc)
        return
    c=client()
    pending_key=None
    newest=None
    for page in c.get_paginator('list_object_versions').paginate(Bucket=settings.storage_bucket, Prefix=prefix):
        # Version listings are ordered by key. Merge markers and versions so a
        # recently rewritten orphan cannot be aged by one of its old versions.
        for obj in sorted(page.get('Versions', [])+page.get('DeleteMarkers', []), key=lambda o:o['Key']):
            if pending_key is not None and obj['Key']!=pending_key:
                yield pending_key, newest
                newest=None
            pending_key=obj['Key']
            newest=max(newest, obj['LastModified']) if newest else obj['LastModified']
    if pending_key is not None: yield pending_key, newest


def delete(key):
    """Idempotent physical removal. S3 delete markers alone do not reclaim bytes."""
    if settings.storage_backend == 'filesystem':
        path=local_path(key)
        try:
            with path.open('rb') as f:
                try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: raise RuntimeError('Storage object is being written')
                path.unlink(missing_ok=True)
        except FileNotFoundError: return
        root=Path(settings.local_storage_path).resolve()
        parent=path.parent
        while parent != root:
            try: parent.rmdir()
            except OSError: break
            parent=parent.parent
        return
    c=client()
    # List by prefix but match the exact key, never similarly named objects.
    for page in c.get_paginator('list_object_versions').paginate(Bucket=settings.storage_bucket, Prefix=key):
        versions=[{'Key':o['Key'], 'VersionId':o['VersionId']}
                  for o in page.get('Versions', [])+page.get('DeleteMarkers', []) if o['Key']==key]
        if versions:
            result=c.delete_objects(Bucket=settings.storage_bucket, Delete={'Objects':versions, 'Quiet':True})
            if result.get('Errors'): raise RuntimeError('Object version deletion failed')


def delete_prefix(prefix):
    for key, _ in objects(prefix): delete(key)


def abort_abandoned_uploads(before, protected):
    if settings.storage_backend == 'filesystem': return
    c=client()
    # Only this application's temporary namespace; never abort a final object write.
    for prefix in ('uploads/', 'tmp/'):
        for page in c.get_paginator('list_multipart_uploads').paginate(Bucket=settings.storage_bucket, Prefix=prefix):
            for upload in page.get('Uploads', []):
                if upload['Initiated'] <= before and not protected(upload['Key']):
                    c.abort_multipart_upload(Bucket=settings.storage_bucket, Key=upload['Key'], UploadId=upload['UploadId'])

def health():
    if settings.storage_backend == 'filesystem':
        root=Path(settings.local_storage_path)
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        with tempfile.TemporaryFile(dir=root) as f:
            f.write(b'health');f.flush()
        return True
    return client().head_bucket(Bucket=settings.storage_bucket)


from contextlib import contextmanager
import shutil


def require_space(size=0, *, directory=None):
    root=Path(directory or settings.worker_temp_path)
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if shutil.disk_usage(root).free < size+settings.storage_reserve_bytes:
        raise OSError(errno.ENOSPC,'Insufficient free storage for sample and safety reserve')


@contextmanager
def scratch(size=0):
    require_space(size)
    # Unlinked on Linux: a worker crash also releases the physical file.
    with tempfile.TemporaryFile(dir=settings.worker_temp_path) as f:
        yield f, Path('/proc/self/fd/'+str(f.fileno()))


@contextmanager
def materialize(key):
    if settings.storage_backend=='filesystem':
        yield local_path(key)
    else:
        c=client();metadata=c.head_object(Bucket=settings.storage_bucket,Key=key)
        with scratch(metadata['ContentLength']) as (f,path):
            c.download_fileobj(settings.storage_bucket,key,f)
            f.flush();f.seek(0)
            yield path


def put_file(key, filename, content_type='application/octet-stream'):
    if settings.storage_backend=='filesystem':
        target=local_path(key);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        require_space(Path(filename).stat().st_size,directory=target.parent)
        fd,temporary=tempfile.mkstemp(prefix='.tmp-',dir=target.parent)
        try:
            with os.fdopen(fd,'wb') as out, Path(filename).open('rb') as source:
                fcntl.flock(out,fcntl.LOCK_EX)
                shutil.copyfileobj(source,out,1024*1024);out.flush();os.fsync(out.fileno())
                os.replace(temporary,target)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
    else:
        # boto3 streams multipart chunks and aborts failed multipart transfers.
        from boto3.s3.transfer import TransferConfig
        with Path(filename).open('rb') as f:
            client().upload_fileobj(f,settings.storage_bucket,key,ExtraArgs={'ContentType':content_type},
                Config=TransferConfig(multipart_chunksize=8*1024*1024,max_concurrency=2))
