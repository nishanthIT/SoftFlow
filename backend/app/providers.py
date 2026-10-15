"""Real provider clients. No synthetic success paths."""
import time
import json
import gzip
import io
from .provider_status import diagnostic
from abc import ABC, abstractmethod
import httpx
from .config import settings as cfg

class Unavailable(Exception): pass
class ProviderTimeout(Exception): pass
class ProviderFailure(Exception): pass

def poll(fetch, done):
    deadline = time.monotonic() + cfg.provider_timeout
    while time.monotonic() < deadline:
        result = fetch()
        if done(result): return result
        time.sleep(min(cfg.provider_poll_interval,max(0,deadline-time.monotonic())))
    raise ProviderTimeout('Provider did not finish within configured deadline')

def checked(response):
    response.raise_for_status()
    return response.json()

def virustotal(data, sha256, consent, checkpoint=lambda d: None):
    raw = {}
    def save(phase):checkpoint({'phase':phase,'raw_responses':raw})
    if not cfg.virustotal_api_key: raise Unavailable('API credentials are not configured')
    with httpx.Client(base_url='https://www.virustotal.com/api/v3',headers={'x-apikey':cfg.virustotal_api_key},timeout=cfg.request_timeout) as c:
        response = c.get('/files/'+sha256)
        if response.status_code == 404:
            if not (consent and cfg.external_uploads_enabled): raise Unavailable('Hash not found; external upload not permitted')
            target = '/files'
            if len(data)>32*1024*1024: target = checked(c.get('/files/upload_url'))['data']
            raw['submission']=checked(c.post(target,files={'file':('sample.exe',data,'application/octet-stream')}))
            task = raw['submission']['data']['id']
            save('Submitted to VirusTotal; awaiting analysis')
            def state():
                raw['analysis']=checked(c.get('/analyses/'+task));save('VirusTotal analysis '+raw['analysis']['data']['attributes']['status']);return raw['analysis']
            poll(state,lambda r:r['data']['attributes']['status']=='completed')
            response = c.get('/files/'+sha256)
        raw['file_report']=checked(response);save('VirusTotal report retrieved')
        attrs = raw['file_report']['data']['attributes']
        stats = attrs.get('last_analysis_stats',{})
        return {'source':'virustotal','sha256':sha256,'stats':stats,'total':sum(stats.values()),'reputation':attrs.get('reputation'),
                'threat_labels':attrs.get('popular_threat_classification',{}),'engines':attrs.get('last_analysis_results',{}),'analysis_date':attrs.get('last_analysis_date'),'raw':raw['file_report'],'raw_responses':raw}

def hybrid_search(c, sha256):
    response = c.get('/search/hash', params={'hash': sha256})
    if response.status_code == 404:
        try: message = response.json().get('message', '')
        except (ValueError, AttributeError): message = ''
        # A route-level 404 is still a failure. Only the provider's explicit
        # missing-hash response is equivalent to an empty search result.
        if message.strip().lower() == 'requested hash not found': return []
    payload = checked(response)
    hits = payload.get('reports') if isinstance(payload, dict) else payload
    if not isinstance(hits, list) or any(not isinstance(hit, dict) for hit in hits):
        raise ProviderFailure('Hybrid Analysis returned an unsupported search response')
    return hits

def hybrid(data, sha256, consent, checkpoint=lambda d: None):
    raw = {}
    def save(phase):checkpoint({'phase':phase,'raw_responses':raw})
    if not cfg.hybrid_analysis_api_key: raise Unavailable('API credentials are not configured')
    with httpx.Client(base_url='https://hybrid-analysis.com/api/v2',headers={'api-key':cfg.hybrid_analysis_api_key,'User-Agent':'Falcon Sandbox','accept':'application/json'},timeout=cfg.request_timeout) as c:
        hits = hybrid_search(c, sha256)
        raw['search_reports']=hits;save('Hybrid Analysis hash lookup completed')
        def finished(r):
            state = str(r.get('state', '')).upper()
            if state in ['ERROR','FAILED']:
                raise ProviderFailure('Hybrid Analysis reports that sandbox execution failed ('+state+')')
            return state in ['SUCCESS','COMPLETED']
        def state(task):
            raw['state']=checked(c.get(f'/report/{task}/state'));save('Hybrid Analysis '+str(raw['state'].get('state','pending')));return raw['state']
        if hits:
            # Prefer a successful execution over failed historic submissions.
            report = next((r for r in hits if str(r.get('state','')).upper() in ['SUCCESS','COMPLETED']), hits[0])
            task = report.get('job_id') or report.get('id')
            if not task: raise ProviderFailure('Hybrid Analysis search result has no report identifier')
            response = c.get(f'/report/{task}/summary')
            if response.status_code == 404:
                raise Unavailable('Hybrid Analysis found the hash, but its report summary is no longer available')
            report = checked(response)
            raw['summary']=report;save('Hybrid Analysis report '+str(report.get('state','unknown')))
            if not finished(report):
                poll(lambda:state(task),finished)
                report = checked(c.get(f'/report/{task}/summary'))
        else:
            if not (consent and cfg.external_uploads_enabled):
                raise Unavailable('No existing Hybrid Analysis report for this hash. File submission requires administrator enablement and consent on a new analysis.')
            submitted = checked(c.post('/submit/file',data={'environment_id':str(cfg.hybrid_environment_id)},files={'file':('sample.exe',data)}))
            raw['submission']=submitted;save('Submitted to Hybrid Analysis; awaiting execution')
            task = submitted.get('job_id') or submitted.get('id')
            if not task: raise ProviderFailure('Hybrid Analysis submission returned no task identifier')
            poll(lambda:state(task),finished)
            report = checked(c.get(f'/report/{task}/summary'))
        if not finished(report):
            raise ProviderFailure('Hybrid Analysis final report is not marked successful')
        if report.get('sha256') and report['sha256'].lower() != sha256.lower():
            raise ProviderFailure('Hybrid Analysis report hash does not match the submitted sample')
        raw['summary']=report;save('Hybrid Analysis summary retrieved')
        # Raw report access is account-dependent. Keep every available summary
        # field even when the optional full-report download is denied.
        try:
            full=c.get(f'/report/{task}/file/json');full.raise_for_status()
            content=full.content
            if content.startswith(b'\x1f\x8b'):
                with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:content=f.read(50*1024*1024+1)
            if len(content)>50*1024*1024:raise ValueError('Report exceeds decoding limit')
            raw['full_report']=json.loads(content)
            raw['full_report_access']={'status':'COMPLETED'}
        except Exception as e:
            raw['full_report_access']=diagnostic('hybrid-analysis',e)
        save('Hybrid Analysis available reports retrieved')
        return {'source':'hybrid-analysis','task_id':task,'state':report.get('state'),'verdict':report.get('verdict'),'threat_score':report.get('threat_score'),
                'malware_family':report.get('vx_family'),'processes':report.get('processes',[]),'domains':report.get('domains',[]),
                'hosts':report.get('hosts',[]),'signatures':report.get('signatures',[]),'mitre_attcks':report.get('mitre_attcks',[]),
                'dropped_files':report.get('extracted_files',[]),'raw':report,'raw_responses':raw}

class SandboxProvider(ABC):
    @abstractmethod
    def submit(self, data): ...
    @abstractmethod
    def get_status(self, task_id): ...
    @abstractmethod
    def get_report(self, task_id): ...

class CuckooCapeProvider(SandboxProvider):
    def __init__(self):
        if not cfg.cuckoo_api_url: raise Unavailable('No isolated Cuckoo/CAPE server is connected. Configure CUCKOO_API_URL and CUCKOO_API_TOKEN after preparing a Windows analysis VM.')
        if not cfg.sandbox_isolation_confirmed: raise Unavailable('Administrator must attest sandbox isolation and snapshot restoration')
        self.cape = cfg.sandbox_kind == 'cape'
        self.client = httpx.Client(base_url=cfg.cuckoo_api_url.rstrip('/')+'/',headers={'Authorization':('Token ' if self.cape else 'Bearer ')+cfg.cuckoo_api_token},timeout=cfg.request_timeout)
    def submit(self, data):
        r = checked(self.client.post('tasks/create/file/' if self.cape else 'tasks/create/file', files={'file':('sample.exe',data)},data={'timeout':'300','enforce_timeout':'1'}))
        if r.get('error'): raise RuntimeError('Sandbox rejected submission')
        return r['data']['task_ids'][0] if self.cape else r['task_id']
    def get_status(self, task_id):
        r = checked(self.client.get(f'tasks/view/{task_id}/' if self.cape else f'tasks/view/{task_id}'))
        return (r.get('data') or r.get('task') or {}).get('status','unknown')
    def get_report(self, task_id):
        r = checked(self.client.get(f'tasks/get/report/{task_id}/' if self.cape else f'tasks/report/{task_id}'))
        if r.get('error'): raise RuntimeError('Sandbox report unavailable')
        return r.get('data',r)
    def run(self, data, checkpoint, previous=None):
        try:
            task = previous or self.submit(data)
            checkpoint({'task_id':task,'provider':cfg.sandbox_kind,'phase':'submitted'})
            def finished(status):
                checkpoint({'task_id':task,'provider':cfg.sandbox_kind,'phase':status})
                if status.startswith('failed'): raise RuntimeError('Sandbox execution failed: '+status)
                return status == 'reported'
            poll(lambda:self.get_status(task),finished)
            report = self.get_report(task)
            return {'task_id':task,'source':cfg.sandbox_kind,'report':report,'snapshot_restoration':'Managed by isolated sandbox; requires operator verification'}
        finally: self.client.close()


class Cuckoo3Provider(SandboxProvider):
    """Cuckoo 3 web API; routes verified against cert-ee/cuckoo3 source."""
    def __init__(self):
        if not cfg.cuckoo_api_url:raise Unavailable('Cuckoo Sandbox API URL is not configured')
        self.client=httpx.Client(base_url=cfg.cuckoo_api_url.rstrip('/')+'/',headers={'Authorization':'Token '+cfg.cuckoo_api_token},timeout=cfg.request_timeout)
    def submit(self,data):
        if not cfg.sandbox_isolation_confirmed:raise Unavailable('Cuckoo VM isolation and snapshot restoration have not been verified')
        platforms=checked(self.client.get('submit/platforms'))
        if not platforms:raise Unavailable('Cuckoo service has no available Windows analysis VM')
        r=self.client.post('submit/file',files={'file':('sample.exe',data)},data={'settings':json.dumps({'timeout':120,'platforms':[{'platform':'windows','os_version':'10'}]})})
        if r.status_code==503:raise Unavailable('Cuckoo submission could not notify its scheduler; Cuckoo core is not running')
        return checked(r)['analysis_id']
    def get_status(self,task_id):
        return checked(self.client.get(f'analysis/{task_id}'))
    def get_report(self,task_id):
        analysis=self.get_status(task_id)
        result={'analysis':analysis,'tasks':[]}
        for task in analysis.get('tasks',[]):
            tid=task['id']
            result['tasks'].append({'task':checked(self.client.get(f'analysis/{task_id}/task/{tid}')),
                'post':checked(self.client.get(f'analysis/{task_id}/task/{tid}/post'))})
        if not result['tasks']:raise ProviderFailure('Cuckoo analysis finished without any task reports')
        return result
    def run(self,data,checkpoint,previous=None):
        try:
            task=previous or self.submit(data)
            checkpoint({'task_id':task,'provider':'cuckoo3','phase':'submitted'})
            def done(r):
                status=r.get('state','unknown')
                checkpoint({'task_id':task,'provider':'cuckoo3','phase':status,'raw_analysis':r})
                if status in ['fatal_error','failed','error']:raise ProviderFailure('Cuckoo dynamic analysis failed; inspect the preserved analysis details')
                return status=='finished'
            poll(lambda:self.get_status(task),done)
            report=self.get_report(task)
            failed=[t for t in report['tasks'] if t['task'].get('state')!='reported']
            if failed:
                checkpoint({'task_id':task,'provider':'cuckoo3','phase':'failed','report':report})
                raise ProviderFailure('Cuckoo finished with failed or incomplete execution tasks')
            return {'task_id':task,'source':'cuckoo3','report':report,'snapshot_restoration':'Enforced by the configured Cuckoo machinery; not independently attested by the API'}
        finally:self.client.close()

def sandbox_provider():
    return Cuckoo3Provider() if cfg.sandbox_kind=='cuckoo3' else CuckooCapeProvider()
