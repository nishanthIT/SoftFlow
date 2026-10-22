import json
import logging
import httpx
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from redis import Redis
from sqlalchemy import select
from .config import settings
from .models import Session, Job, Sample, Engine, ENGINES, TERMINAL, now, record_models
from . import providers, storage, static, policy
from .provider_status import diagnostic, sanitize
from .reporting import build_report
from fastapi.encoders import jsonable_encoder

log=logging.getLogger('sentinel.worker')
celery=Celery('sentinel',broker=settings.redis_url,backend=settings.redis_url)
celery.conf.update(task_acks_late=True,task_reject_on_worker_lost=True,worker_prefetch_multiplier=1,task_serializer='json',accept_content=['json'],broker_transport_options={'visibility_timeout':14400},beat_schedule={'dispatch':{'task':'app.tasks.dispatch','schedule':15.0}})

def update(job_id,name,status,data=None,reason=None):
    with Session.begin() as db:
        e=db.scalar(select(Engine).where(Engine.analysis_id==job_id,Engine.name==name))
        e.status=status
        if data is not None: e.data=sanitize(data)
        e.reason=reason
        if status=='RUNNING' and e.started_at is None: e.started_at=now()
        if status in TERMINAL: e.completed_at=now()
    log.info(json.dumps({'analysis_id':job_id,'engine':name,'status':status,'reason':reason}))

def snapshot(job_id):
    with Session() as db:
        return {e.name:{'status':e.status,'data':e.data,'reason':e.reason} for e in db.scalars(select(Engine).where(Engine.analysis_id==job_id))}

def execute(job_id,name,fn):
    existing=snapshot(job_id)[name]
    if existing['status'] in TERMINAL: return existing['data']
    update(job_id,name,'RUNNING')
    try:
        data=fn()
        if data is None:
            if name in ['behavior','network']:
                upstream=snapshot(job_id)['sandbox']
                raise providers.Unavailable('Sandbox telemetry is unavailable: '+(upstream.get('reason') or 'the sandbox report does not contain the required observations'))
            raise providers.Unavailable('Required upstream telemetry is unavailable')
        update(job_id,name,'COMPLETED',data)
        return data
    except providers.Unavailable as e: update(job_id,name,'UNAVAILABLE',reason=sanitize(str(e)),data={**snapshot(job_id)[name]['data'],'diagnostic':{'code':'ANALYSIS_UNAVAILABLE','message':sanitize(str(e))}})
    except providers.ProviderFailure as e: update(job_id,name,'FAILED',reason=sanitize(str(e)),data={**snapshot(job_id)[name]['data'],'diagnostic':{'code':'PROVIDER_FAILED','message':sanitize(str(e))}})
    except (providers.ProviderTimeout,SoftTimeLimitExceeded) as e:
        message=f'{name} analysis is still pending or exceeded its configured deadline'
        update(job_id,name,'TIMEOUT',reason=message,data={**snapshot(job_id)[name]['data'],'diagnostic':{'code':'ANALYSIS_TIMEOUT','message':message}})
    except Exception as e:
        detail=diagnostic(name,e)
        update(job_id,name,detail['status'],reason=detail['message'],data={**snapshot(job_id)[name]['data'],'diagnostic':detail})
    return {}

@celery.task(name='app.tasks.dispatch')
def dispatch():
    # DB-backed outbox: durable queued jobs are retried even if broker publish failed.
    with Session() as db:
        ids=list(db.scalars(select(Job.id).where(Job.status.in_(['QUEUED','RUNNING']))))
    redis=Redis.from_url(settings.redis_url)
    for id in ids:
        if not redis.exists('analysis-lock:'+id): run.delay(id)

@celery.task(name='app.tasks.run',soft_time_limit=7100,time_limit=7200)
def run(job_id):
    redis=Redis.from_url(settings.redis_url)
    lock=redis.lock('analysis-lock:'+job_id,timeout=7250,blocking=False)
    if not lock.acquire(blocking=False): return
    try:
        with Session.begin() as db:
            job=db.get(Job,job_id)
            if not job or job.status in ('COMPLETED','FAILED'): return
            job.status='RUNNING'; job.started_at=job.started_at or now()
            sample=db.get(Sample,job.sample_id); sha=sample.sha256; consent=job.consent; filename=job.submitted_filename or sample.filename
            hashes={'sha256':sha,'sha1':sample.sha1,'md5':sample.md5}
        data=storage.get('samples/'+sha)
        import hashlib
        actual={name:hashlib.new(name,data).hexdigest() for name in hashes}
        if actual!=hashes:raise ValueError('Stored sample integrity check failed')
        execute(job_id,'validation',lambda:{'format':'PE executable','validated':True})
        execute(job_id,'hashing',lambda:actual)
        st=execute(job_id,'static',lambda:static.analyze(data))
        yr=execute(job_id,'yara',lambda:static.scan_yara(data))
        execute(job_id,'virustotal',lambda:providers.virustotal(data,sha,consent,lambda d:update(job_id,'virustotal','RUNNING',d)))
        execute(job_id,'hybrid-analysis',lambda:providers.hybrid(data,sha,consent,lambda d:update(job_id,'hybrid-analysis','RUNNING',d)))
        prior=snapshot(job_id)['sandbox']['data']
        def sandbox():
            provider=providers.sandbox_provider()
            checkpoint=lambda d:update(job_id,'sandbox','RUNNING',d)
            if settings.sandbox_kind=='cuckoo3':return provider.run(data,checkpoint,prior,filename=filename)
            return provider.run(data,checkpoint,prior.get('task_id'))
        sb=execute(job_id,'sandbox',sandbox)
        be=execute(job_id,'behavior',lambda:policy.behavior(sb))
        net=execute(job_id,'network',lambda:policy.network(sb))
        states=snapshot(job_id)
        ai=execute(job_id,'ai',lambda:policy.ai_detect(st,net,states['static']['status']=='COMPLETED',states['network']['status']=='COMPLETED',be))
        execute(job_id,'correlation',lambda:{'schema_version':1,'sample':hashes,'sources':{k:v for k,v in snapshot(job_id).items() if k not in ['correlation','verdict','report']}})
        vd=execute(job_id,'verdict',lambda:policy.verdict(snapshot(job_id)))
        mapping={'static_results':st,'sandbox_results':sb,'network_events':net,'yara_matches':yr,'ai_indicators':ai,'behavior_events':be,'verdicts':vd,'iocs':{'static_urls':st.get('urls',[]),'static_ips':st.get('ips',[]),'runtime_domains':net.get('domains',[]),'runtime_ips':net.get('ips',[])}}
        with Session.begin() as db:
            for table,payload in mapping.items():
                model=record_models[table]
                db.query(model).filter_by(analysis_id=job_id).delete()
                db.add(model(analysis_id=job_id,data=payload))
        update(job_id,'report','RUNNING')
        # Write the final snapshot before committing completion. Storage failure
        # fails the job instead of claiming that a downloadable report exists.
        with Session.begin() as db:
            job=db.get(Job,job_id);job.status='COMPLETED';job.completed_at=now()
            rows=list(db.scalars(select(Engine).where(Engine.analysis_id==job_id)))
            report_engine=next(e for e in rows if e.name=='report')
            report_engine.status='COMPLETED';report_engine.completed_at=job.completed_at;report_engine.reason=None
            report_engine.data={'object_key':'reports/'+job_id+'.json','format':'json','schema_version':'2.0','summary':vd}
            serialize=lambda row:{c.name:getattr(row,c.name) for c in row.__table__.columns}
            sample_data=serialize(db.get(Sample,job.sample_id));sample_data['filename']=filename
            report=build_report(serialize(job),sample_data,[serialize(e) for e in rows],job.completed_at.isoformat())
            storage.put('reports/'+job_id+'.json',json.dumps(jsonable_encoder(sanitize(report)),indent=2).encode(),'application/json')
    except Exception as e:
        log.error(json.dumps({'analysis_id':job_id,'error':type(e).__name__}))
        with Session.begin() as db:
            job=db.get(Job,job_id); job.status='FAILED'; job.completed_at=now()
            for row in db.scalars(select(Engine).where(Engine.analysis_id==job_id)):
                if row.status not in TERMINAL:
                    row.status='FAILED';row.completed_at=now()
                    row.reason='Report persistence/finalization failed' if row.name=='report' and row.started_at else 'Worker could not complete job'
                    row.data={**row.data,'diagnostic':{'code':'WORKER_FAILED','message':row.reason,'error_type':type(e).__name__}}
        raise
    finally:
        try: lock.release()
        except Exception: pass
