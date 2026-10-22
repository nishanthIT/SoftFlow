import asyncio,hashlib,json,struct
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI,UploadFile,File,Form,HTTPException,Response,Request
from fastapi.responses import StreamingResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel,Field
from sqlalchemy import select,text
from sqlalchemy.exc import IntegrityError
from redis import Redis
from .config import settings
from .models import Session,User,Sample,Job,Engine,Audit,ENGINES,TERMINAL,engine
from . import policy
from .models import record_models
from . import storage
from .provider_status import sanitize, check as check_provider
from .reporting import build_report, outcome
from .approval import recommend, criteria
from typing import Literal

@asynccontextmanager
async def lifespan(app):
    if settings.mock_analysis: raise RuntimeError('Mock analysis is not supported in production')
    with Session.begin() as db:
        # Retain historical user foreign keys; new actions share an unauthenticated actor.
        if not db.scalar(select(User).where(User.username=='LAN workspace')):
            db.add(User(username='LAN workspace',role='workspace'))
    yield
app=FastAPI(title='SentinelScan API',version='1.1.0',lifespan=lifespan,docs_url='/api/docs',openapi_url='/api/openapi.json')

@app.middleware('http')
async def security(request,call_next):
    if request.method in ['POST','PUT','PATCH','DELETE']:
        origin=request.headers.get('origin')
        allowed=[str(request.base_url).rstrip('/'), *settings.allowed_origins]
        # The local API binds to loopback with uvicorn proxy interpretation off.
        # Next forwards the browser's host while proxying to API_INTERNAL_URL.
        if request.client and request.client.host in ('127.0.0.1','::1'):
            host=request.headers.get('x-forwarded-host')
            proto=request.headers.get('x-forwarded-proto',request.url.scheme)
            if host and ',' not in host and proto in ('http','https'):
                allowed.append(proto+'://'+host)
        if request.headers.get('sec-fetch-site')=='cross-site' or (origin and origin.rstrip('/') not in allowed):
            return Response('Origin rejected',status_code=403)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Cache-Control']='no-store'
    return response
def serialize(row): return {c.name:getattr(row,c.name) for c in row.__table__.columns}
def new_job(db,sample_id,consent,filename=None):
    actor=db.scalar(select(User.id).where(User.username=='LAN workspace'))
    job=Job(sample_id=sample_id,user_id=actor,consent=consent,submitted_filename=filename); db.add(job); db.flush()
    for name in ENGINES: db.add(Engine(analysis_id=job.id,name=name))
    db.add(Audit(user_id=job.user_id,action='analysis.created',data={'analysis_id':job.id,'sample_id':sample_id,'external_consent':consent}))
    return job.id
@app.post('/api/samples',status_code=201)
async def upload(file:UploadFile=File(...),external_consent:bool=Form(False)):
    filename=Path((file.filename or '').replace('\\','/')).name[:255]
    if not filename.lower().endswith('.exe'): raise HTTPException(422,'Only .exe files are accepted')
    data=bytearray()
    while chunk:=await file.read(1024*1024):
        data.extend(chunk)
        if len(data)>settings.max_upload_mb*1024*1024: raise HTTPException(413,'File exceeds upload limit')
    if len(data)<64 or data[:2]!=b'MZ': raise HTTPException(422,'Invalid DOS header')
    offset=struct.unpack_from('<I',data,60)[0]
    if offset+24>len(data) or data[offset:offset+4]!=b'PE\0\0': raise HTTPException(422,'Invalid PE header')
    if not struct.unpack_from('<H',data,offset+22)[0]&2: raise HTTPException(422,'PE is not executable')
    if struct.unpack_from('<H',data,offset+22)[0]&0x2000: raise HTTPException(422,'DLL submissions are unsupported; submit a Windows EXE')
    if struct.unpack_from('<H',data,offset+4)[0] not in (0x14c,0x8664): raise HTTPException(422,'Unsupported executable architecture; the configured Windows workflow accepts x86 and x64 EXE files')
    hashes={k:hashlib.new(k,data).hexdigest() for k in ['sha256','sha1','md5']}
    def persist():
        storage.put('samples/'+hashes['sha256'],bytes(data))
        with Session() as db:
            sample=db.scalar(select(Sample).where(Sample.sha256==hashes['sha256'])); duplicate=bool(sample)
            if not sample:
                sample=Sample(**hashes,filename=filename,size=len(data)); db.add(sample)
                try: db.commit()
                except IntegrityError:
                    db.rollback(); sample=db.scalar(select(Sample).where(Sample.sha256==hashes['sha256'])); duplicate=True
            id=new_job(db,sample.id,external_consent,filename); db.commit()
            return {'analysis_id':id,'sample_id':sample.id,'duplicate':duplicate,**hashes}
    return await asyncio.to_thread(persist)
class Start(BaseModel):
    sample_id:str
    external_consent:bool=False
@app.post('/api/analysis',status_code=201)
def start(body:Start):
    with Session.begin() as db:
        if not db.get(Sample,body.sample_id): raise HTTPException(404,'Sample not found')
        return {'analysis_id':new_job(db,body.sample_id,body.external_consent)}
@app.get('/api/samples')
def samples(limit:int=50,offset:int=0):
    with Session() as db:
        rows=list(db.scalars(select(Sample).order_by(Sample.created_at.desc()).limit(max(1,min(limit,100))).offset(max(0,offset))))
        result=[]
        for s in rows:
            j=db.scalar(select(Job).where(Job.sample_id==s.id).order_by(Job.created_at.desc()))
            v=db.scalar(select(Engine).where(Engine.analysis_id==j.id,Engine.name=='verdict')) if j else None
            result.append({**serialize(s),'latest_analysis_id':j.id if j else None,'status':j.status if j else None,'verdict':v.data.get('security') if v else None})
        return result
@app.get('/api/samples/{id}')
def sample(id:str):
    with Session() as db:
        row=db.get(Sample,id)
        if not row: raise HTTPException(404,'Sample not found')
        return {**serialize(row),'analyses':[serialize(j) for j in db.scalars(select(Job).where(Job.sample_id==id).order_by(Job.created_at.desc()))]}
def analysis_data(id):
    with Session() as db:
        j=db.get(Job,id)
        if not j: raise HTTPException(404,'Analysis not found')
        engines=[serialize(e) for e in db.scalars(select(Engine).where(Engine.analysis_id==id))]
        engines.sort(key=lambda e:ENGINES.index(e['name']))
        sample=serialize(db.get(Sample,j.sample_id))
        sample['filename']=j.submitted_filename or sample['filename']
        reviews=record_models['analyst_reviews']
        decisions=[serialize(r) for r in db.scalars(select(reviews).where(reviews.analysis_id==id).order_by(reviews.created_at.desc(),reviews.id.desc()))]
        return sanitize({**serialize(j),'approval':recommend(j.status,engines),'decisions':decisions,'final_status':outcome(j.status,engines),'sample':sample,'engines':engines,'progress':round(100*sum(e['status'] in TERMINAL for e in engines)/len(ENGINES))})
@app.get('/api/analysis/{id}')
@app.get('/api/analysis/{id}/status')
def analysis(id:str): return analysis_data(id)
@app.get('/api/analysis/{id}/report')
def report(id:str,response:Response):
    result=analysis_data(id)
    if result['status'] not in ['COMPLETED','FAILED']:raise HTTPException(409,'Analysis is still running; export is available when processing ends')
    completed=next(e for e in result['engines'] if e['name']=='report')
    if completed['status']=='COMPLETED' and completed['data'].get('schema_version')=='2.0':
        try: exported=json.loads(storage.get('reports/'+id+'.json'))
        except Exception:raise HTTPException(503,'Stored report is unavailable; retry after checking report storage')
        exported.setdefault('approval',result['approval'])
        exported['decisions']=result['decisions']
        exported.setdefault('vulnerability_assessment',{'status':'NOT_PERFORMED','findings':[]})
    else: exported=build_report(result,result['sample'],result['engines'])
    response.headers['Content-Disposition']='attachment; filename="sentinelscan-'+result['id']+'.json"'
    return sanitize(exported)

class Decision(BaseModel):
    decision: Literal['APPROVE','REJECT','REVIEW_REQUIRED']
    reason: str = Field(min_length=1,max_length=2000)

@app.post('/api/analysis/{id}/decision',status_code=201)
def decide(id:str,body:Decision):
    if not body.reason.strip():raise HTTPException(422,'A decision reason is required')
    with Session.begin() as db:
        job=db.scalar(select(Job).where(Job.id==id).with_for_update())
        if not job:raise HTTPException(404,'Analysis not found')
        engines=[serialize(e) for e in db.scalars(select(Engine).where(Engine.analysis_id==id))]
        recommendation=recommend(job.status,engines)
        if body.decision=='APPROVE' and recommendation['recommendation']!='APPROVE':
            raise HTTPException(409,'Approval requires completed analysis meeting the acceptance criteria')
        entry=record_models['analyst_reviews'](analysis_id=id,data={
            'decision':body.decision,'reason':body.reason.strip(),'actor':'LAN workspace (unauthenticated)',
            'assessment':recommendation})
        db.add(entry);db.flush()
        db.add(Audit(action='analysis.decision',data={'analysis_id':id,'review_id':entry.id,'decision':body.decision}))
        return sanitize(serialize(entry))
@app.get('/api/analysis/{id}/events')
async def events(id:str,request:Request):
    await asyncio.to_thread(analysis_data,id)
    async def stream():
        previous=None
        for _ in range(1800):
            if await request.is_disconnected(): break
            data=await asyncio.to_thread(analysis_data,id)
            encoded=json.dumps(jsonable_encoder(data))
            if encoded!=previous: yield 'data: '+encoded+'\n\n'; previous=encoded
            else: yield ': heartbeat\n\n'
            if data['status'] in ['COMPLETED','FAILED']: break
            await asyncio.sleep(2)
    return StreamingResponse(stream(),media_type='text/event-stream',headers={'X-Accel-Buffering':'no'})
@app.get('/api/analysis/{id}/{engine_name}')
def engine_result(id:str,engine_name:str):
    data=analysis_data(id)
    result=next((e for e in data['engines'] if e['name']==engine_name),None)
    if not result: raise HTTPException(404,'Engine not found')
    return result
@app.get('/api/settings')
def config():
    return {'authentication_required':False,'approval_policy':criteria(),'providers':[{'name':'VirusTotal','configured':bool(settings.virustotal_api_key)},{'name':'Hybrid Analysis','configured':bool(settings.hybrid_analysis_api_key)},{'name':'CAPE / Cuckoo','configured':bool(settings.cuckoo_api_url),'isolation_confirmed':settings.sandbox_isolation_confirmed}], 'external_uploads_enabled':settings.external_uploads_enabled,'max_upload_mb':settings.max_upload_mb,'secrets':'Managed through server environment; never returned to the browser'}
@app.get('/api/rules')
def rules():
    paths=list(Path(settings.yara_path).glob('**/*.yar*'))
    providers=json.loads(Path(settings.ai_signatures_path).read_text())
    return {'yara':[{'name':p.name,'content':p.read_text()} for p in paths],'ai':providers}
@app.get('/health')
def health():
    checks={}
    for name,fn in [('database',lambda:engine.connect()),('redis',lambda:Redis.from_url(settings.redis_url).ping()),('storage',storage.health)]:
        try:
            obj=fn()
            if hasattr(obj,'close'): obj.close()
            checks[name]='CONNECTED'
        except Exception: checks[name]='UNAVAILABLE'
    return Response(json.dumps(checks),media_type='application/json',status_code=200 if all(v=='CONNECTED' for v in checks.values()) else 503)
@app.get('/health/providers')
@app.get('/api/providers/health')
def provider_health():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(check_provider,['virustotal','hybrid-analysis','sandbox']))
    from .tasks import celery
    try: workers=list((celery.control.inspect(timeout=1).ping() or {}).keys())
    except Exception: workers=[]
    return {'providers':results,'workers':workers}

@app.get('/api/analysis/{id}/{engine_name}/raw')
def raw_report(id:str,engine_name:str):
    data=engine_result(id,engine_name)
    return {'analysis_id':id,'engine':engine_name,'status':data['status'],'reason':data['reason'],
            'raw':data['data'].get('raw_responses',data['data'].get('raw',data['data'].get('report',data['data'].get('raw_analysis',{}))))}

@app.get('/api/admin')
def admin():
    with Session() as db:
        return {'users':[serialize(u) for u in db.scalars(select(User))], 'jobs':[serialize(j) for j in db.scalars(select(Job).order_by(Job.created_at.desc()).limit(100))], 'audit_logs':[serialize(a) for a in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(100))]}
