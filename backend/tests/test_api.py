"""In-memory DB and object-store test doubles only; never production providers."""
import hashlib
import json
import struct
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import main,tasks,storage
from app.config import settings
from app.models import Base, ENGINES

@pytest.fixture
def client(monkeypatch):
    db=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(db)
    session=sessionmaker(db,expire_on_commit=False)
    monkeypatch.setattr(main,'Session',session);monkeypatch.setattr(tasks,'Session',session)
    from app import ssl_checks
    monkeypatch.setattr(ssl_checks,'Session',session)
    monkeypatch.setattr(settings,'mock_analysis',False)
    objects={}
    monkeypatch.setattr(storage,'put',lambda key,data,*args:objects.__setitem__(key,data))
    monkeypatch.setattr(storage,'get',lambda key:objects[key])
    from pathlib import Path
    from contextlib import contextmanager
    import tempfile
    monkeypatch.setattr(storage,'put_file',lambda key,path,*args:storage.put(key,Path(path).read_bytes(),*args))
    @contextmanager
    def materialize(key):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample';path.write_bytes(objects[key]);yield path
    monkeypatch.setattr(storage,'materialize',materialize)
    with TestClient(main.app) as c: yield c

def pe():
    data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0';struct.pack_into('<H',data,150,2)
    struct.pack_into('<H',data,132,0x8664)
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
    assert job['status']=='QUEUED' and job['progress']==0 and len(job['engines'])==len(ENGINES)
    assert job['sample']['filename']=='good.exe'
    assert job['consent'] is False
    renamed=client.get('/api/analysis/'+second['analysis_id']).json()
    assert renamed['sample']['filename']=='again.exe'
    assert client.get('/api/analysis/'+r['analysis_id']+'/report').status_code==409

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
    assert job['final_status']=='COMPLETED_WITH_GAPS'
    exported=client.get('/api/analysis/'+id+'/report').json()
    stored=json.loads(storage.get('reports/'+id+'.json'))
    assert exported==stored
    assert exported['schema_version']=='2.0'
    assert exported['sample']['filename']=='header-only.exe'
    assert exported['sample']['size']==len(pe())
    assert exported['steps'][-1]['status']=='COMPLETED'
    assert all(s['status'] not in ['RUNNING','QUEUED'] for s in exported['steps'])
    assert exported['summary']['errors_or_gaps']==len(exported['errors'])
    assert not any(g['engine'] in ['verdict','report'] for g in exported['verdict']['coverage_gaps'])
    assert exported['vulnerability_assessment']['status']=='IDENTIFICATION_REQUIRED'
    assert stages['dns']['status']=='UNAVAILABLE'
    assert storage.get('reports/'+id+'.pdf').startswith(b'%PDF-')
    pdf=client.get('/api/analysis/'+id+'/report.pdf')
    assert pdf.status_code==200 and pdf.content.startswith(b'%PDF-')
    assert pdf.headers['content-type']=='application/pdf'
    monkeypatch.setattr(storage,'get',lambda _:(_ for _ in ()).throw(OSError('offline')))
    assert client.get('/api/analysis/'+id+'/report').status_code==503


def test_report_write_failure_fails_job_and_remains_exportable(client,monkeypatch):
    for name in ['virustotal_api_key','hybrid_analysis_api_key','cuckoo_api_url']:
        monkeypatch.setattr(settings,name,'')
    class Lease:
        def acquire(self,**kw):return True
        def release(self):pass
    class LockStore:
        def lock(self,*a,**kw):return Lease()
    monkeypatch.setattr(tasks.Redis,'from_url',lambda *a,**kw:LockStore())
    identifier=client.post('/api/samples',files={'file':('storage-error.exe',pe())}).json()['analysis_id']
    monkeypatch.setattr(storage,'put',lambda *a:(_ for _ in ()).throw(OSError('storage offline')))
    with pytest.raises(OSError):tasks.run.run(identifier)
    result=client.get('/api/analysis/'+identifier+'/report').json()
    assert result['status']=='FAILED' and result['final_status']=='FAILED'
    assert result['steps'][-1]['status']=='FAILED'
    assert any(e['stage']=='report' for e in result['errors'])
    assert all(s['status'] not in ['RUNNING','QUEUED'] for s in result['steps'])


def test_repeated_worker_loss_stops_retrying_and_closes_stages(client,monkeypatch):
    from app.models import Job
    class Lease:
        def acquire(self,**kw):return True
        def release(self):pass
    class LockStore:
        def lock(self,*a,**kw):return Lease()
    monkeypatch.setattr(tasks.Redis,'from_url',lambda *a,**kw:LockStore())
    identifier=client.post('/api/samples',files={'file':('recovery.exe',pe())}).json()['analysis_id']
    with tasks.Session.begin() as db:
        job=db.get(Job,identifier);job.status='RUNNING';job.attempts=3
    with pytest.raises(RuntimeError,match='recovery limit'):tasks.run.run(identifier)
    result=client.get('/api/analysis/'+identifier).json()
    assert result['status']=='FAILED' and result['completed_at']
    assert all(stage['status']=='FAILED' for stage in result['engines'])
    tasks.run.run(identifier)  # Redelivery of a terminal job is harmless.


def test_development_mode_can_run_without_login(client):
    assert client.get('/api/samples').status_code==200
    assert client.get('/api/admin').status_code==200
    assert client.get('/api/settings').json()['authentication_required'] is False
    assert client.get('/api/auth/session').status_code==404
    assert client.post('/api/auth/login',json={'username':'admin','password':'unused'}).status_code==404
    assert not client.cookies


def test_lan_same_origin_upload_and_foreign_origin_rejection(client):
    headers={'Host':'172.20.10.3:3100','Origin':'http://172.20.10.3:3100'}
    assert client.post('/api/samples',headers=headers,files={'file':('lan.exe',pe())}).status_code==201
    headers['Origin']='http://other.invalid:3100'
    assert client.post('/api/samples',headers=headers,files={'file':('lan.exe',pe())}).status_code==403


def test_incomplete_analysis_cannot_be_approved_and_decisions_are_audited(client):
    identifier=client.post('/api/samples',files={'file':('review.exe',pe())}).json()['analysis_id']
    path='/api/analysis/'+identifier
    assert client.post(path+'/decision',json={'decision':'APPROVE','reason':'Please approve'}).status_code==409
    assert client.post(path+'/decision',json={'decision':'REVIEW_REQUIRED','reason':' '}).status_code==422
    assert client.post(path+'/decision',json={'decision':'REVIEW_REQUIRED','reason':'Waiting for sandbox evidence'}).status_code==201
    data=client.get(path).json()
    assert data['approval']['recommendation']=='REVIEW_REQUIRED'
    assert data['decisions'][0]['data']['assessment']['analysis_status']=='QUEUED'
    assert client.get('/api/admin').json()['audit_logs'][0]['action']=='analysis.decision'


@pytest.mark.parametrize('machine,flags',[(0xaa64,2),(0x8664,0x2002)])
def test_unsupported_executables_rejected(client,machine,flags):
    data=bytearray(pe());struct.pack_into('<H',data,132,machine);struct.pack_into('<H',data,150,flags)
    assert client.post('/api/samples',files={'file':('unsupported.exe',bytes(data))}).status_code==422


def test_final_report_appends_decision_history_without_changing_evidence(client):
    from app.models import Job, Engine
    from sqlalchemy import select
    identifier=client.post('/api/samples',files={'file':('failed.exe',pe())}).json()['analysis_id']
    with main.Session.begin() as db:
        db.get(Job,identifier).status='FAILED'
        for e in db.scalars(select(Engine).where(Engine.analysis_id==identifier)):
            e.status='FAILED';e.reason='Test of a failed execution'
    path='/api/analysis/'+identifier
    assert client.post(path+'/decision',json={'decision':'REVIEW_REQUIRED','reason':'Missing execution evidence'}).status_code==201
    assert client.post(path+'/decision',json={'decision':'REJECT','reason':'Workspace declines this submission'}).status_code==201
    response=client.get(path+'/report');result=response.json()
    assert 'attachment;' in response.headers['content-disposition']
    assert result['approval']['recommendation']=='REVIEW_REQUIRED'
    assert len(result['decisions'])==2 and result['decisions'][0]['data']['decision']=='REJECT'
    assert all(e['status']=='FAILED' for e in result['engines'])
    assert result['vulnerability_assessment']['status']=='NOT_PERFORMED'


def test_certificate_feature_is_available_without_login(client):
    assert client.get('/api/ssl-checks').status_code==200
    result=client.post('/api/ssl-checks',files={'file':('domains.txt',b'example.org')})
    assert result.status_code==201 and result.json()['status']=='QUEUED'
    assert client.get('/api/ssl-checks/'+result.json()['id']).status_code==200
    assert 'app.tasks.ssl_run' in tasks.celery.tasks
    assert not client.cookies


def test_presentation_mode_does_not_contact_sandbox(monkeypatch):
    from app import provider_status,providers
    monkeypatch.setattr(settings,'presentation_mode',True)
    monkeypatch.setattr(provider_status.httpx,'get',lambda *a,**k:pytest.fail('No sandbox request'))
    status=provider_status.check('sandbox')
    assert status['status']=='DISABLED' and status['execution_ready'] is False
    with pytest.raises(providers.Unavailable,match='presentation mode'):providers.sandbox_provider()


def test_multipart_accepts_name_version_without_changing_uploaded_sample(client):
    response=client.post('/api/samples',files={'file':('fixture.exe',pe())},data={'software_name':'7-Zip','software_version':'16.00'})
    assert response.status_code==201
    job=client.get('/api/analysis/'+response.json()['analysis_id']).json()
    assert job['software_identity']=={'name':'7-Zip','version':'16.00','vendor':''}
    assert response.json()['sha256']==hashlib.sha256(pe()).hexdigest()
    assert client.post('/api/samples',files={'file':('fixture.exe',pe())},data={'software_name':'7-Zip'}).status_code==422
