"""Create a private bucket, including S3-compatible stores without AWS access blocks."""
import json
import time
from botocore.exceptions import ClientError
from .storage import client
from .config import settings

def ensure_private_bucket(c):
    try: c.head_bucket(Bucket=settings.storage_bucket)
    except ClientError as e:
        if e.response['Error']['Code'] in ['404','NoSuchBucket','NotFound']: c.create_bucket(Bucket=settings.storage_bucket)
        else: raise
    try:
        policy=json.loads(c.get_bucket_policy(Bucket=settings.storage_bucket)['Policy'])
        for statement in policy.get('Statement',[]):
            principal=statement.get('Principal')
            if statement.get('Effect')=='Allow' and (principal=='*' or isinstance(principal,dict) and principal.get('AWS')=='*'):
                raise RuntimeError('Refusing a bucket with anonymous access policy')
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucketPolicy','NoSuchPolicy','404']: raise
    acl=c.get_bucket_acl(Bucket=settings.storage_bucket)
    if any(g.get('Grantee',{}).get('URI','').endswith(('/AllUsers','/AuthenticatedUsers')) for g in acl.get('Grants',[])):
        raise RuntimeError('Refusing a bucket with public ACL grants')
    if settings.storage_backend == 'minio':
        # MinIO may route this unsupported AWS operation to CreateBucket and
        # return MalformedXML rather than NotImplemented. Do not send it.
        print('MinIO bucket policy and ACL verified private; AWS public-access-block API is not applicable',flush=True)
        return
    # AWS S3 requires this safeguard. Never suppress malformed XML, permission,
    # or unsupported-operation errors for an S3 deployment.
    c.put_public_access_block(Bucket=settings.storage_bucket,PublicAccessBlockConfiguration={'BlockPublicAcls':True,'IgnorePublicAcls':True,'BlockPublicPolicy':True,'RestrictPublicBuckets':True})

if __name__=='__main__':
    for attempt in range(30):
        try:
            ensure_private_bucket(client())
            break
        except Exception:
            if attempt==29: raise
            time.sleep(2)
