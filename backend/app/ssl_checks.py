"""Durable domain-list processing and Excel exports, independent of Cuckoo."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import PurePosixPath
from fastapi import APIRouter,File,HTTPException,UploadFile,Response
from sqlalchemy import select,func
from .models import Session,SSLCheck,now
from .retention import expires_at,utc
from .lifecycle import storage_guard
from . import ssl_checker as checker

router=APIRouter(prefix='/api/ssl-checks',tags=['SSL expiry checker'])

def serialize(scan,detail=False):
    return {'id':scan.id,'filename':scan.filename,'status':scan.status,'total':len(scan.domains),
        'completed':len(scan.results),'created_at':scan.created_at,'completed_at':scan.completed_at,
        'expires_at':expires_at(scan.created_at),'error':scan.error,
        'summary':dict(Counter(row['status'] for row in scan.results)),
        **({'results':scan.results} if detail else {})}

@router.post('',status_code=201)
async def upload(file:UploadFile=File(...)):
    filename=PurePosixPath((file.filename or '').replace('\\','/')).name
    try:
        if not filename.lower().endswith('.txt'):raise HTTPException(422,'Upload a .txt file with one domain per line')
        data=await file.read(checker.MAX_UPLOAD_BYTES+1)
        if len(data)>checker.MAX_UPLOAD_BYTES:raise HTTPException(413,'Text file exceeds 256 KiB')
        try:domains=checker.parse_upload(data)
        except ValueError as error:raise HTTPException(422,str(error))
    finally:await file.close()
    with Session.begin() as db:
        storage_guard(db)
        pending=db.scalar(select(func.count()).select_from(SSLCheck).where(SSLCheck.status.in_(['QUEUED','RUNNING'])))
        if pending>=4:raise HTTPException(429,'Four certificate checks are active; wait for one to finish')
        scan=SSLCheck(filename=filename[:255],domains=domains,results=[]);db.add(scan);db.flush()
        return serialize(scan,True)

@router.get('')
def history():
    with Session() as db:return [serialize(scan) for scan in db.scalars(select(SSLCheck).order_by(SSLCheck.created_at.desc()).limit(50))]

def get_scan(db,identifier):
    scan=db.get(SSLCheck,identifier)
    if not scan:raise HTTPException(404,'Check not found or its seven-day retention period has ended')
    return scan

@router.get('/{identifier}')
def detail(identifier:str):
    with Session() as db:return serialize(get_scan(db,identifier),True)

@router.get('/{identifier}/report.xlsx')
def report(identifier:str):
    with Session() as db:
        scan=get_scan(db,identifier)
        if scan.status not in ('COMPLETED','FAILED'):raise HTTPException(409,'The check is still running')
        if not scan.results:raise HTTPException(409,'No results are available for export')
        data=checker.create_excel(scan.results,{'Source file':scan.filename,'Scan ID':scan.id,
            'Created (UTC)':utc(scan.created_at).isoformat(),'Expires (UTC)':expires_at(scan.created_at).isoformat(),
            'Status':scan.status,'Error':scan.error or ''})
    return Response(data,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition':'attachment; filename="ssl_expiry_results.xlsx"'})

def run_scan(identifier,session=None):
    session=session or Session
    with session.begin() as db:
        scan=db.get(SSLCheck,identifier)
        if not scan or scan.status not in ('QUEUED','RUNNING'):return
        if scan.attempts>=3:
            scan.status='FAILED';scan.completed_at=now();scan.error='Worker recovery limit reached; completed results are preserved.';return
        scan.attempts+=1;scan.status='RUNNING';results=list(scan.results)
        finished={row['domain'] for row in results};remaining=[domain for domain in scan.domains if domain not in finished]
    try:
        with ThreadPoolExecutor(max_workers=checker.MAX_WORKERS) as pool:
            futures={pool.submit(checker.check_domain,domain):domain for domain in remaining}
            for future in as_completed(futures):
                try:result=future.result()
                except Exception as error:result=checker.error_result(futures[future],'CHECK_ERROR',type(error).__name__)
                results.append(result);results.sort(key=lambda row:row['domain'])
                with session.begin() as db:db.get(SSLCheck,identifier).results=list(results)
        with session.begin() as db:
            scan=db.get(SSLCheck,identifier);scan.status='COMPLETED';scan.completed_at=now()
    except Exception as error:
        with session.begin() as db:
            scan=db.get(SSLCheck,identifier);scan.status='FAILED';scan.completed_at=now()
            scan.error='Check interrupted ('+type(error).__name__+'); completed results are preserved.'
        raise
