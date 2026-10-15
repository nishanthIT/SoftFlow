import boto3
import os
import tempfile
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
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        return
    client().put_object(Bucket=settings.storage_bucket, Key=key, Body=data, ContentType=content_type)
def get(key):
    if settings.storage_backend == 'filesystem': return local_path(key).read_bytes()
    response = client().get_object(Bucket=settings.storage_bucket, Key=key)
    try: return response['Body'].read()
    finally: response['Body'].close()


def local_path(key):
    root=Path(settings.local_storage_path).resolve()
    target=(root/key).resolve()
    if not target.is_relative_to(root) or target==root:
        raise ValueError('Invalid storage object key')
    return target

def health():
    if settings.storage_backend == 'filesystem':
        root=Path(settings.local_storage_path)
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        with tempfile.TemporaryFile(dir=root) as f:
            f.write(b'health');f.flush()
        return True
    return client().head_bucket(Bucket=settings.storage_bucket)
