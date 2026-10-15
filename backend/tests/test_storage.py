import pytest
from botocore.exceptions import ClientError
from app.config import settings
from app.init_storage import ensure_private_bucket

class MinioContract:
    def head_bucket(self,**kw): pass
    def get_bucket_policy(self,**kw):raise ClientError({'Error':{'Code':'NoSuchBucketPolicy'}},'GetBucketPolicy')
    def get_bucket_acl(self,**kw):return {'Grants':[]}
    def put_public_access_block(self,**kw):
        raise AssertionError('MinIO must never receive the AWS-only public-access-block request')

@pytest.fixture(autouse=True)
def backend(monkeypatch):
    monkeypatch.setattr(settings,'storage_backend','minio')

def test_minio_skips_unsupported_public_access_block():
    ensure_private_bucket(MinioContract())

def test_public_acl_rejected():
    store=MinioContract()
    store.get_bucket_acl=lambda **kw:{'Grants':[{'Grantee':{'URI':'http://acs.amazonaws.com/groups/global/AllUsers'}}]}
    with pytest.raises(RuntimeError):ensure_private_bucket(store)

def test_public_policy_rejected():
    store=MinioContract()
    store.get_bucket_policy=lambda **kw:{'Policy':'{"Statement":[{"Effect":"Allow","Principal":"*"}]}'}
    with pytest.raises(RuntimeError):ensure_private_bucket(store)

def test_s3_enables_all_access_blocks(monkeypatch):
    monkeypatch.setattr(settings,'storage_backend','s3')
    store=MinioContract();calls=[]
    store.put_public_access_block=lambda **kw:calls.append(kw)
    ensure_private_bucket(store)
    assert len(calls)==1
    assert calls[0]['PublicAccessBlockConfiguration']=={
        'BlockPublicAcls':True,'IgnorePublicAcls':True,'BlockPublicPolicy':True,'RestrictPublicBuckets':True}

@pytest.mark.parametrize('code',['MalformedXML','AccessDenied','NotImplemented'])
def test_s3_errors_are_not_suppressed(monkeypatch,code):
    monkeypatch.setattr(settings,'storage_backend','s3')
    store=MinioContract()
    def fail(**kw):raise ClientError({'Error':{'Code':code}},'PutPublicAccessBlock')
    store.put_public_access_block=fail
    with pytest.raises(ClientError):ensure_private_bucket(store)
