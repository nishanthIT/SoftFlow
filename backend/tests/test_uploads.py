"""Resumable uploads use an isolated DB and real temporary disk storage."""
import hashlib
import os
import resource
import struct
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine,event,select,func
from sqlalchemy.orm import sessionmaker
from app import main,storage,uploads,retention,sample_io
from app.config import settings
from app.models import Base,Upload,UploadChunk,Sample,Job,User,now


@pytest.fixture
def environment(tmp_path,monkeypatch):
    engine=create_engine('sqlite:///'+str(tmp_path/'db.sqlite'),connect_args={'check_same_thread':False})
    @event.listens_for(engine,'connect')
    def foreign_keys(connection,_):connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    session=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(main,'Session',session);monkeypatch.setattr(retention,'Session',session)
    monkeypatch.setattr(settings,'storage_backend','filesystem')
    monkeypatch.setattr(settings,'local_storage_path',str(tmp_path/'objects'))
    monkeypatch.setattr(settings,'worker_temp_path',str(tmp_path/'scratch'))
    monkeypatch.setattr(settings,'max_upload_mb',2048)
    monkeypatch.setattr(settings,'storage_reserve_bytes',0)
    monkeypatch.setattr(settings,'upload_chunk_bytes',8*1024*1024)
    with session.begin() as db:db.add(User(username='LAN workspace'))
    yield session
    engine.dispose()


def pe():
    data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,60,128)
    data[128:132]=b'PE\0\0';struct.pack_into('<H',data,132,0x8664);struct.pack_into('<H',data,150,2)
    return bytes(data)


def write(session,identifier,offset,data):return uploads.chunk(session,identifier,offset,data,hashlib.sha256(data).hexdigest())


def test_api_resumes_retries_and_finalizes_once(environment):
    payload=pe();digest=hashlib.sha256(payload).hexdigest()
    with TestClient(main.app) as client:
        row=client.post('/api/uploads',json={'filename':'../../sample.exe','size':len(payload)}).json()
        identifier=row['id'];assert row['filename']=='sample.exe'
        headers={'X-Chunk-SHA256':hashlib.sha256(payload[:256]).hexdigest()}
        response=client.put(f'/api/uploads/{identifier}/chunks/0',content=payload[:256],headers=headers)
        assert response.status_code==200 and response.json()['received']==256
        assert client.put(f'/api/uploads/{identifier}/chunks/0',content=payload[:256],headers=headers).json()['received']==256
        assert client.get(f'/api/uploads/{identifier}').json()['received']==256
        assert client.post(f'/api/uploads/{identifier}/complete').status_code==409
        headers={'X-Chunk-SHA256':hashlib.sha256(payload[256:]).hexdigest()}
        assert client.put(f'/api/uploads/{identifier}/chunks/256',content=payload[256:],headers=headers).status_code==200
        response=client.post(f'/api/uploads/{identifier}/complete')
        assert response.status_code==201 and response.json()['sha256']==digest
        identifier_job=response.json()['analysis_id']
        assert client.post(f'/api/uploads/{identifier}/complete').json()['analysis_id']==identifier_job
    with environment() as db:
        assert db.scalar(select(func.count()).select_from(Job))==1
        assert db.get(Upload,identifier).state=='COMPLETED'
    assert storage.get('samples/'+digest)==payload


def test_chunk_integrity_order_size_and_conflicting_retry(environment,monkeypatch):
    identifier=uploads.create(environment,'file.exe',512,False)['id']
    with pytest.raises(main.HTTPException) as error:uploads.chunk(environment,identifier,0,b'x'*256,'wrong')
    assert error.value.status_code==422
    with pytest.raises(main.HTTPException) as error:write(environment,identifier,256,b'x'*256)
    assert error.value.status_code==409
    write(environment,identifier,0,b'x'*256)
    with pytest.raises(main.HTTPException) as error:write(environment,identifier,0,b'y'*256)
    assert error.value.status_code==409
    with pytest.raises(main.HTTPException) as error:write(environment,identifier,256,b'x'*257)
    assert error.value.status_code==413
    monkeypatch.setattr(settings,'upload_chunk_bytes',128)
    with pytest.raises(main.HTTPException) as error:write(environment,identifier,256,b'x'*256)
    assert error.value.status_code==413
    assert uploads.get(environment,identifier)['received']==256


def test_failed_finalization_is_retryable_and_releases_scratch(environment,monkeypatch):
    identifier=uploads.create(environment,'file.exe',512,False)['id'];write(environment,identifier,0,pe())
    actual=storage.put_file
    monkeypatch.setattr(storage,'put_file',lambda *a:(_ for _ in ()).throw(OSError('full')))
    with pytest.raises(main.HTTPException) as error:uploads.complete(environment,identifier)
    assert error.value.status_code==507
    assert uploads.get(environment,identifier)['state']=='OPEN'
    assert list(__import__('pathlib').Path(settings.worker_temp_path).iterdir())==[]
    monkeypatch.setattr(storage,'put_file',actual)
    assert uploads.complete(environment,identifier)['sha256']==hashlib.sha256(pe()).hexdigest()


def test_tampered_storage_and_invalid_pe_are_rejected(environment):
    identifier=uploads.create(environment,'file.exe',512,False)['id'];write(environment,identifier,0,pe())
    storage.put(f'uploads/{identifier}/chunks/0',b'x'*512)
    with pytest.raises(main.HTTPException) as error:uploads.complete(environment,identifier)
    assert error.value.status_code==422
    uploads.abandon(environment,identifier)
    other=uploads.create(environment,'invalid.exe',512,False)['id'];write(environment,other,0,b'x'*512)
    with pytest.raises(main.HTTPException) as error:uploads.complete(environment,other)
    assert error.value.status_code==422
    with environment() as db:assert db.scalar(select(func.count()).select_from(Job))==0


def test_disk_space_bounds_and_exact_two_gib_metadata(environment,monkeypatch):
    row=uploads.create(environment,'limit.exe',2*1024**3,False)
    assert row['size']==2147483648
    with pytest.raises(main.HTTPException) as error:uploads.create(environment,'over.exe',2*1024**3+1,False)
    assert error.value.status_code==413
    monkeypatch.setattr(storage,'require_space',lambda *a,**k:(_ for _ in ()).throw(OSError('full')))
    with pytest.raises(main.HTTPException) as error:uploads.create(environment,'full.exe',512,False)
    assert error.value.status_code==507
    with pytest.raises(main.HTTPException) as error:write(environment,row['id'],0,pe())
    assert error.value.status_code==507 and uploads.get(environment,row['id'])['received']==0


def test_abandon_and_retention_remove_staging_but_preserve_active_job(environment):
    abandon=uploads.create(environment,'abandon.exe',512,False)['id'];write(environment,abandon,0,pe())
    uploads.abandon(environment,abandon);uploads.abandon(environment,abandon)
    assert list(storage.objects('uploads/'+abandon+'/'))==[]
    old=uploads.create(environment,'old.exe',512,False)['id'];write(environment,old,0,pe())
    recent=uploads.create(environment,'recent.exe',512,False)['id'];write(environment,recent,0,pe())
    done=uploads.create(environment,'done.exe',512,False)['id'];write(environment,done,0,pe())
    result=uploads.complete(environment,done);at=now()
    with environment.begin() as db:
        for identifier in (old,done):db.get(Upload,identifier).updated_at=at-timedelta(hours=2)
        db.get(Job,result['analysis_id']).status='RUNNING'
    assert retention.cleanup(at)['failed']==0
    with environment() as db:
        assert not db.get(Upload,old) and not db.get(Upload,done) and db.get(Upload,recent)
        assert db.get(Job,result['analysis_id']).status=='RUNNING'
        assert db.scalar(select(func.count()).select_from(UploadChunk))==1
    assert not list(storage.objects('uploads/'+old+'/')) and not list(storage.objects('uploads/'+done+'/'))
    assert storage.get('samples/'+result['sha256'])==pe()


def test_bounded_storage_read_and_scratch_release(environment):
    storage.put('tmp/read',b'x'*1024)
    with pytest.raises(ValueError):storage.get('tmp/read',max_bytes=512)
    with storage.scratch() as (out,path):
        out.write(pe());out.flush();assert sample_io.hashes(path)['sha256']==hashlib.sha256(pe()).hexdigest()
        assert path.exists()
    assert not path.exists()


@pytest.mark.skipif(os.environ.get('RUN_LARGE_UPLOAD_TESTS')!='1',reason='Set RUN_LARGE_UPLOAD_TESTS=1 for physical disk and RSS verification')
@pytest.mark.parametrize('megabytes',[32,100,500,1024,2048])
def test_real_large_upload_bounded_memory(environment,megabytes):
    # Harmless header fixture: stored and hashed only, never submitted to a VM.
    total=megabytes*1024*1024;before=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    identifier=uploads.create(environment,'storage-fixture.exe',total,False)['id']
    block=bytes(settings.upload_chunk_bytes);digest=hashlib.sha256()
    for offset in range(0,total,len(block)):
        part=block if offset else pe()+block[len(pe()):]
        part=part[:min(len(part),total-offset)];digest.update(part);write(environment,identifier,offset,part)
    result=uploads.complete(environment,identifier)
    assert result['sha256']==digest.hexdigest()
    assert storage.local_path('samples/'+result['sha256']).stat().st_size==total
    with environment() as db:assert db.get(Sample,result['sample_id']).size==total
    growth_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss-before
    assert growth_kib<128*1024
    print({'size_bytes':total,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'rss_growth_kib':growth_kib,'sha256_verified':True})


def test_software_identity_survives_resumable_upload_and_reanalysis(environment):
    from app import tasks
    with TestClient(main.app) as client:
        identity={'name':'7-Zip','version':'16.00','vendor':''}
        started=client.post('/api/uploads',json={'filename':'metadata-free.exe','size':512,'software_identity':identity})
        assert started.status_code==201
        identifier=started.json()['id'];write(environment,identifier,0,pe())
        result=client.post('/api/uploads/'+identifier+'/complete');assert result.status_code==201
        job=result.json()['analysis_id']
        assert client.get('/api/analysis/'+job).json()['software_identity']==identity
        again=client.post('/api/analysis',json={'sample_id':result.json()['sample_id'],'software_identity':{**identity,'version':'16.02'}})
        assert again.status_code==201
        assert client.get('/api/analysis/'+again.json()['analysis_id']).json()['software_identity']['version']=='16.02'
        invalid=client.post('/api/uploads',json={'filename':'test.exe','size':512,'software_identity':{'name':'7-Zip','version':' '}})
        assert invalid.status_code==422
