import asyncio,hashlib,json,struct,errno,re
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
from . import storage, uploads, sample_io
from .provider_status import sanitize, check as check_provider
from .reporting import build_report, outcome
from .approval import recommend, criteria
from .lifecycle import storage_guard
from .retention import expiration
from typing import Literal
from .software_identity import SoftwareIdentity

@asynccontextmanager
async def lifespan(app):
    if settings.mock_analysis: raise RuntimeError('Mock analysis is not supported in production')
    with Session.begin() as db:
        # Preserve historical users; new records belong to the shared LAN workspace.
        if not db.scalar(select(User).where(User.username=='LAN workspace')):
            db.add(User(username='LAN workspace',role='workspace'))
    yield
app=FastAPI(title='SentinelScan API',version='1.1.0',lifespan=lifespan,docs_url='/api/docs',openapi_url='/api/openapi.json')
from .ssl_checks import router as ssl_router
app.include_router(ssl_router)

@app.middleware('http')
async def security(request,call_next):
    length=request.headers.get('content-length','')
    if request.url.path=='/api/ssl-checks' and length.isdigit() and int(length)>300*1024:
        return Response('Domain list exceeds 256 KiB',status_code=413)
    if request.url.path=='/api/samples' and length.isdigit() and int(length)>(settings.max_upload_mb+1)*1024*1024:
        return Response('Upload exceeds the configured file limit',status_code=413)
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
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    return response
def serialize(row):
    data={c.name:getattr(row,c.name) for c in row.__table__.columns}
    if isinstance(row, Job): data.update(expiration(row))
    return data
def new_job(db,sample_id,consent,filename=None,software_identity=None):
    actor=db.scalar(select(User.id).where(User.username=='LAN workspace'))
    job=Job(sample_id=sample_id,user_id=actor,consent=consent,submitted_filename=filename,software_identity=software_identity or {}); db.add(job); db.flush()
    for name in ENGINES: db.add(Engine(analysis_id=job.id,name=name))
    db.add(Audit(user_id=job.user_id,action='analysis.created',data={'analysis_id':job.id,'sample_id':sample_id,'external_consent':consent}))
    return job.id
@app.post('/api/samples',status_code=201)
async def upload(file:UploadFile=File(...),external_consent:bool=Form(False),
                 software_name:str=Form('',max_length=160),software_version:str=Form('',max_length=128)):
    filename=uploads.name(file.filename or '')
    identity=None
    if software_name.strip() or software_version.strip():
        try:identity=SoftwareIdentity(name=software_name,version=software_version).model_dump()
        except ValueError:raise HTTPException(422,'Provide both a valid software name and version')
    # Starlette spools multipart files; copy in bounded chunks into an unlinked
    # scratch file. The browser uses the resumable endpoints below.
    try:
        with storage.scratch() as (out,path):
            size=0
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>settings.max_upload_mb*1024*1024:raise HTTPException(413,'File exceeds upload limit')
                storage.require_space(len(chunk));out.write(chunk)
            out.flush()
            def persist():
                with Session.begin() as db:
                    storage_guard(db,shared=True)
                    try:return uploads.persist(db,path,filename,external_consent,identity)
                    except ValueError as error:raise HTTPException(422,str(error))
            return await asyncio.to_thread(persist)
    except OSError as error:
        if error.errno in (errno.ENOSPC,errno.EDQUOT):raise HTTPException(507,'Insufficient storage for upload')
        raise

class UploadStart(BaseModel):
    filename:str=Field(max_length=1024)
    size:int=Field(ge=64,le=2147483648)
    external_consent:bool=False
    software_identity:SoftwareIdentity|None=None

@app.post('/api/uploads',status_code=201)
def create_upload(body:UploadStart):
    return uploads.create(Session,body.filename,body.size,body.external_consent,body.software_identity.model_dump() if body.software_identity else None)

@app.get('/api/uploads/{identifier}')
def upload_status(identifier:str):return uploads.get(Session,identifier)

@app.put('/api/uploads/{identifier}/chunks/{offset}')
async def upload_chunk(identifier:str,offset:int,request:Request):
    if offset<0:raise HTTPException(422,'Invalid chunk offset')
    length=request.headers.get('content-length','')
    if length.isdigit() and int(length)>settings.upload_chunk_bytes:raise HTTPException(413,'Chunk exceeds upload limit')
    await asyncio.to_thread(uploads.get,Session,identifier,True)
    data=bytearray()
    try:
        async with asyncio.timeout(120):
            async for part in request.stream():
                data.extend(part)
                if len(data)>settings.upload_chunk_bytes:raise HTTPException(413,'Chunk exceeds upload limit')
    except TimeoutError:raise HTTPException(408,'Chunk upload timed out; retry this chunk')
    return await asyncio.to_thread(uploads.chunk,Session,identifier,offset,bytes(data),request.headers.get('x-chunk-sha256',''))

@app.post('/api/uploads/{identifier}/complete',status_code=201)
def complete_upload(identifier:str):return uploads.complete(Session,identifier)

@app.delete('/api/uploads/{identifier}',status_code=204)
def cancel_upload(identifier:str):uploads.abandon(Session,identifier)

class Start(BaseModel):
    sample_id:str
    external_consent:bool=False
    software_identity:SoftwareIdentity|None=None
@app.post('/api/analysis',status_code=201)
def start(body:Start):
    with Session.begin() as db:
        storage_guard(db, shared=True)
        if not db.get(Sample,body.sample_id): raise HTTPException(404,'Sample not found')
        return {'analysis_id':new_job(db,body.sample_id,body.external_consent,software_identity=body.software_identity.model_dump() if body.software_identity else None)}
@app.get('/api/samples')
def samples(limit:int=50,offset:int=0):
    with Session() as db:
        rows=list(db.scalars(select(Sample).order_by(Sample.created_at.desc()).limit(max(1,min(limit,100))).offset(max(0,offset))))
        result=[]
        for s in rows:
            j=db.scalar(select(Job).where(Job.sample_id==s.id).order_by(Job.created_at.desc()))
            v=db.scalar(select(Engine).where(Engine.analysis_id==j.id,Engine.name=='verdict')) if j else None
            result.append({**serialize(s),**(expiration(j) if j else {}),'latest_analysis_id':j.id if j else None,'status':j.status if j else None,'verdict':v.data.get('security') if v else None})
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
        return sanitize({**serialize(j),'approval':recommend(j.status,engines),'decisions':decisions,'final_status':outcome(j.status,engines),'sample':sample,'engines':engines,'progress':round(100*sum(e['status'] in TERMINAL for e in engines)/max(1,len(engines)))})
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

@app.get('/api/analysis/{id}/report.pdf')
def pdf_report(id:str):
    from .pdf_report import render
    # Render the export snapshot with current decision history. The original
    # PDF is also persisted at completion and removed by retention.
    exported=report(id,Response())
    return Response(render(exported),media_type='application/pdf',headers={
        'Content-Disposition':'attachment; filename="sentinelscan-'+exported['analysis_id']+'.pdf"'})

@app.get('/api/analysis/{id}/artifacts/{task_id}/{filename}')
def artifact(id:str,task_id:str,filename:str):
    if not re.fullmatch(r'\d{8}-[A-Z0-9]{6}_\d+',task_id) or not re.fullmatch(r'capture\.pcap|[0-9]{1,14}\.(?:jpg|png)',filename):
        raise HTTPException(404,'Artifact not found')
    result=engine_result(id,'sandbox')
    key=f'artifacts/{id}/{task_id}/{filename}'
    entry=next((f for f in result['data'].get('artifacts',{}).get('files',[]) if f.get('object_key')==key),None)
    if not entry:raise HTTPException(404,'Artifact not found')
    def stream():
        with Session.begin() as db:
            storage_guard(db,shared=True)
            if not db.get(Job,id):return
            with storage.materialize(key) as path,open(path,'rb') as source:
                while chunk:=source.read(1024*1024):yield chunk
    return StreamingResponse(stream(),media_type='application/octet-stream',headers={
        'Content-Disposition':'attachment; filename="'+filename+'"','Content-Length':str(entry['size'])})

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
    return {'presentation_mode':settings.presentation_mode,'authentication_required':False,'sandbox_enabled':settings.sandbox_enabled,'runtime':settings.app_env,'approval_policy':criteria(),'providers':[{'name':'VirusTotal','configured':bool(settings.virustotal_api_key)},{'name':'Hybrid Analysis','configured':bool(settings.hybrid_analysis_api_key)},{'name':'CAPE / Cuckoo','configured':bool(settings.cuckoo_api_url),'isolation_confirmed':settings.sandbox_isolation_confirmed}], 'external_uploads_enabled':settings.external_uploads_enabled,'max_upload_mb':settings.max_upload_mb,'secrets':'Managed through server environment; never returned to the browser'}
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
