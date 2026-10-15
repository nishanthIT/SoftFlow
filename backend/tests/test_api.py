"""In-memory DB and object-store test doubles only; never production providers."""
import hashlib
import struct
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import main,tasks,storage
from app.config import settings
from app.models import Base
from app.auth import require_user

@pytest.fixture
def client(monkeypatch):
    db=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(db)
    session=sessionmaker(db,expire_on_commit=False)
    monkeypatch.setattr(main,'Session',session);monkeypatch.setattr(tasks,'Session',session)
    monkeypatch.setattr(settings,'auth_secret','x'*40);monkeypatch.setattr(settings,'admin_password','test-password-only')
    monkeypatch.setattr(settings,'mock_analysis',False)
    main.app.dependency_overrides[require_user]=lambda:'admin'
    objects={}
    monkeypatch.setattr(storage,'put',lambda key,data,*args:objects.__setitem__(key,data))
    monkeypatch.setattr(storage,'get',lambda key:objects[key])
    with TestClient(main.app) as c: yield c
    main.app.dependency_overrides.clear()

def pe():
    data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0';struct.pack_into('<H',data,150,2)
    return bytes(data)

def test_upload_rejects_non_executable(client):
    assert client.post('/api/samples',files={'file':('bad.exe',b'not PE')}).status_code==422
    assert client.post('/api/samples',files={'file':('bad.txt',pe())}).status_code==422

def test_upload_hash_duplicate_and_job(client):
    data=pe()
    first=client.post('/api/samples',files={'file':('../../good.exe',data)},data={'external_consent':'false'})
    assert first.status_code==201
    r=first.json();assert r['sha256']==hashlib.sha256(data).hexdigest()
    second=client.post('/api/samples',files={'file':('again.exe',data)}).json()
    assert second['duplicate'] and second['sample_id']==r['sample_id']
    assert second['analysis_id']!=r['analysis_id']
    job=client.get('/api/analysis/'+r['analysis_id']).json()
    assert job['status']=='QUEUED' and job['progress']==0 and len(job['engines'])==13
    assert job['sample']['filename']=='good.exe'
    assert job['consent'] is False

def test_cross_origin_mutation_rejected(client):
    assert client.post('/api/samples',headers={'Origin':'https://evil.example'},files={'file':('test.exe',pe())}).status_code==403

def test_settings_never_expose_secrets(client,monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','secret-needle')
    response=client.get('/api/settings')
    assert 'secret-needle' not in response.text

def test_stage_failure_does_not_prevent_next(client):
    id=client.post('/api/samples',files={'file':('test.exe',pe())}).json()['analysis_id']
    tasks.execute(id,'virustotal',lambda:(_ for _ in ()).throw(RuntimeError('secret error')))
    tasks.execute(id,'ai',lambda:{'status':'INCONCLUSIVE'})
    stages=tasks.snapshot(id)
    assert stages['virustotal']['status']=='FAILED'
    assert 'secret' not in stages['virustotal']['reason']
    assert stages['ai']['status']=='COMPLETED'

def test_real_pipeline_without_external_providers(client,monkeypatch):
    from pathlib import Path
    root=Path(__file__).resolve().parents[2]
    monkeypatch.setattr(settings,'ai_signatures_path',str(root/'ai-signatures/providers.json'))
    monkeypatch.setattr(settings,'yara_path',str(root/'yara/rules'))
    for name in ['virustotal_api_key','hybrid_analysis_api_key','cuckoo_api_url']:
        monkeypatch.setattr(settings,name,'')
    class Lease:
        def acquire(self,**kw):return True
        def release(self):pass
    class LocalLockStore:
        def lock(self,*args,**kwargs):return Lease()
    monkeypatch.setattr(tasks.Redis,'from_url',lambda *args,**kwargs:LocalLockStore())
    id=client.post('/api/samples',files={'file':('header-only.exe',pe())}).json()['analysis_id']
    tasks.run.run(id)
    job=client.get('/api/analysis/'+id).json()
    assert job['status']=='COMPLETED' and job['progress']==100
    stages={s['name']:s for s in job['engines']}
    assert stages['virustotal']['status']=='UNAVAILABLE'
    assert stages['network']['status']=='UNAVAILABLE'
    assert stages['verdict']['data']['security']=='INCONCLUSIVE'
    assert stages['report']['status']=='COMPLETED'
