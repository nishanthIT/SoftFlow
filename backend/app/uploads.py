"""Sequential resumable uploads with idempotent, checksummed chunk commits."""
import hashlib
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import select, func, delete
from sqlalchemy.exc import IntegrityError
from .models import Upload, UploadChunk, Sample, Job, now
from .config import settings
from .lifecycle import storage_guard
from . import storage, sample_io


def name(value):
    value=Path(value.replace('\\','/')).name[:255]
    if not value.lower().endswith('.exe'):raise HTTPException(422,'Only .exe files are accepted')
    return value


def view(row):
    return {'id':row.id,'filename':row.filename,'size':row.size,'received':row.received,
            'state':row.state,'analysis_id':row.analysis_id,'chunk_bytes':settings.upload_chunk_bytes}


def create(session,filename,size,consent,software_identity=None):
    filename=name(filename)
    if not 64<=size<=settings.max_upload_mb*1024*1024:raise HTTPException(413,f'File must be between 64 bytes and {settings.max_upload_mb} MiB')
    with session.begin() as db:
        storage_guard(db)
        if db.scalar(select(func.count()).select_from(Upload).where(Upload.state=='OPEN'))>=settings.upload_max_pending:
            raise HTTPException(429,'Too many pending uploads; resume an existing upload or retry later')
        try:
            storage.require_space(size)
            if settings.storage_backend=='filesystem':storage.require_space(size,directory=settings.local_storage_path)
        except OSError:raise HTTPException(507,'Insufficient storage for this upload')
        row=Upload(filename=filename,size=size,consent=consent,software_identity=software_identity or {});db.add(row);db.flush()
        return view(row)


def get(session,identifier,touch=False):
    with session.begin() as db:
        row=db.scalar(select(Upload).where(Upload.id==identifier).with_for_update())
        if not row:raise HTTPException(404,'Upload expired or not found')
        if touch:row.updated_at=now()
        return view(row)


def chunk(session,identifier,offset,data,sha256):
    if not data or len(data)>settings.upload_chunk_bytes:raise HTTPException(413,'Invalid chunk size')
    digest=hashlib.sha256(data).hexdigest()
    if digest!=sha256:raise HTTPException(422,'Chunk checksum mismatch; retry this chunk')
    with session.begin() as db:
        storage_guard(db,shared=True)
        row=db.scalar(select(Upload).where(Upload.id==identifier).with_for_update())
        if not row:raise HTTPException(404,'Upload expired or not found')
        if row.state!='OPEN':raise HTTPException(409,'Upload is no longer open')
        previous=db.get(UploadChunk,(identifier,offset))
        if previous:
            if previous.sha256!=digest or previous.size!=len(data):raise HTTPException(409,'Chunk conflicts with a previous upload')
            row.updated_at=now();return view(row)
        if offset!=row.received:raise HTTPException(409,'Chunk offset does not match the received byte count')
        if offset+len(data)>row.size:raise HTTPException(413,'Chunk exceeds declared file size')
        try:
            if settings.storage_backend=='filesystem':storage.require_space(len(data),directory=settings.local_storage_path)
            storage.put(f'uploads/{identifier}/chunks/{offset}',data)
        except OSError:raise HTTPException(507,'Upload storage is unavailable or full')
        db.add(UploadChunk(upload_id=identifier,offset=offset,size=len(data),sha256=digest))
        row.received+=len(data);row.updated_at=now()
        return view(row)


def persist(db,path,filename,consent,software_identity=None):
    from .main import new_job
    sample_io.validate(path);hashes=sample_io.hashes(path)
    sample=db.scalar(select(Sample).where(Sample.sha256==hashes['sha256']).with_for_update())
    duplicate=bool(sample)
    if not sample:
        try:
            with db.begin_nested():
                sample=Sample(**hashes,filename=filename,size=sample_io.length(path));db.add(sample);db.flush()
        except IntegrityError:
            sample=db.scalar(select(Sample).where(Sample.sha256==hashes['sha256']).with_for_update());duplicate=True
    storage.put_file('samples/'+hashes['sha256'],path)
    identifier=new_job(db,sample.id,consent,filename,software_identity)
    return {'analysis_id':identifier,'sample_id':sample.id,'duplicate':duplicate,**hashes}


def complete(session,identifier):
    with session.begin() as db:
        storage_guard(db,shared=True)
        row=db.scalar(select(Upload).where(Upload.id==identifier).with_for_update())
        if not row:raise HTTPException(404,'Upload expired or not found')
        if row.state=='COMPLETED':return {'analysis_id':row.analysis_id}
        if row.received!=row.size:raise HTTPException(409,'Upload is incomplete')
        if row.state!='OPEN':raise HTTPException(409,'Upload cannot be finalized')
        row.state='FINALIZING'
        try:
            with storage.scratch(row.size) as (out,path):
                for part in db.scalars(select(UploadChunk).where(UploadChunk.upload_id==identifier).order_by(UploadChunk.offset)):
                    if part.offset!=out.tell() or not 0<part.size<=settings.upload_chunk_bytes:
                        raise HTTPException(422,'Stored chunk sequence is invalid; create a new upload')
                    data=storage.get(f'uploads/{identifier}/chunks/{part.offset}',max_bytes=settings.upload_chunk_bytes)
                    if len(data)!=part.size or hashlib.sha256(data).hexdigest()!=part.sha256:
                        raise HTTPException(422,'Stored chunk integrity check failed; create a new upload')
                    out.write(data)
                out.flush()
                if out.tell()!=row.size:raise HTTPException(422,'Assembled upload size mismatch')
                result=persist(db,path,row.filename,row.consent,row.software_identity)
        except ValueError as error:raise HTTPException(422,str(error))
        except OSError:raise HTTPException(507,'Unable to finalize upload storage')
        row.state='COMPLETED';row.analysis_id=result['analysis_id'];row.updated_at=now()
        # Keep chunks until commit succeeds. The hourly cleaner removes them,
        # preserving a safe retry after any file/database commit failure.
        return result


def abandon(session,identifier):
    with session.begin() as db:
        storage_guard(db)
        row=db.scalar(select(Upload).where(Upload.id==identifier).with_for_update())
        if not row:return
        if row.state=='COMPLETED':return
        storage.delete_prefix('uploads/'+identifier+'/')
        db.execute(delete(UploadChunk).where(UploadChunk.upload_id==identifier));db.delete(row)
