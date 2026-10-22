"""Typed, non-secret diagnostic status shared by health checks and job results."""
import hashlib,time,threading
import httpx
from .config import settings

NAMES={'virustotal':'VirusTotal','hybrid-analysis':'Hybrid Analysis','sandbox':'Cuckoo Sandbox'}
_CACHE={};_LOCK=threading.Lock()

def sanitize(value):
    secrets=[settings.virustotal_api_key,settings.hybrid_analysis_api_key,settings.cuckoo_api_token,settings.minio_secret_key]
    if isinstance(value,str):
        for secret in secrets:
            if secret and len(secret)>7:value=value.replace(secret,'[REDACTED]')
        return value
    if isinstance(value,dict):return {k:sanitize(v) for k,v in value.items()}
    if isinstance(value,list):return [sanitize(v) for v in value]
    return value

def diagnostic(name,error):
    label=NAMES.get(name,name)
    code='ANALYSIS_FAILED';state='FAILED';message=f'{label} analysis failed ({type(error).__name__})'
    retry_after=None
    if isinstance(error,httpx.TimeoutException):
        code='TIMEOUT';state='TIMEOUT';message=f'{label} API request timed out'
    elif isinstance(error,httpx.RequestError):
        code='NETWORK_UNAVAILABLE';state='UNAVAILABLE';message=f'{label} network/API unavailable ({type(error).__name__})'
    elif isinstance(error,httpx.HTTPStatusError):
        status=error.response.status_code
        if status==401:code='INVALID_API_KEY';message=f'{label} authentication failed: invalid API key'
        elif status==403:code='ACCESS_DENIED';message=f'{label} access denied: API key lacks permission for this operation'
        elif status==429:
            code='RATE_LIMITED';state='UNAVAILABLE';message=f'{label} rate limit reached'
            raw=error.response.headers.get('retry-after','')
            if raw.isdigit():retry_after=min(int(raw),86400)
        elif status==404:code='ANALYSIS_UNAVAILABLE';state='UNAVAILABLE';message=f'{label} requested report or API endpoint was not found'
        elif status>=500:code='API_UNAVAILABLE';state='UNAVAILABLE';message=f'{label} service unavailable (HTTP {status})'
        else:code='REQUEST_REJECTED';message=f'{label} request rejected (HTTP {status})'
    elif isinstance(error,(ValueError,KeyError,TypeError)):
        code='INVALID_RESPONSE';message=f'{label} returned an invalid API response ({type(error).__name__})'
    return {'code':code,'status':state,'message':message,'retry_after_seconds':retry_after}

def check(name,refresh=False):
    key={'virustotal':settings.virustotal_api_key,'hybrid-analysis':settings.hybrid_analysis_api_key,'sandbox':settings.cuckoo_api_token}.get(name,'')
    configured=bool(settings.cuckoo_api_url) if name=='sandbox' else bool(key)
    identity=(name,hashlib.sha256(key.encode()).hexdigest(),settings.cuckoo_api_url,settings.sandbox_kind,settings.sandbox_isolation_confirmed,settings.sandbox_os_version)
    with _LOCK:
        cached=_CACHE.get(identity)
        if not refresh and cached and time.monotonic()-cached[0]<settings.provider_health_ttl:return cached[1]
    result={'name':NAMES[name],'id':name,'configured':configured,'checked_at':None}
    if name=='sandbox':result.update(execution_ready=False,isolation_confirmed=settings.sandbox_isolation_confirmed,kind=settings.sandbox_kind)
    from datetime import datetime,timezone
    if not configured:result.update(status='NOT_CONFIGURED',message=f'{NAMES[name]} '+('API URL is not configured' if name=='sandbox' else 'API key is not configured'))
    else:
        try:
            if name=='virustotal':
                # A public, known hash validates authentication without embedding
                # the API key in a request URL or submitting customer data.
                url='https://www.virustotal.com/api/v3/files/'+hashlib.sha256(b'').hexdigest()
                headers={'x-apikey':key}
            elif name=='hybrid-analysis':url='https://hybrid-analysis.com/api/v2/key/current';headers={'api-key':key,'User-Agent':'Falcon Sandbox','accept':'application/json'}
            else:
                suffix='/submit/platforms' if settings.sandbox_kind=='cuckoo3' else '/cuckoo/status/' if settings.sandbox_kind=='cape' else '/cuckoo/status'
                url=settings.cuckoo_api_url.rstrip('/')+suffix
                headers={'Authorization':('Bearer ' if settings.sandbox_kind=='cuckoo' else 'Token ')+key}
            r=httpx.get(url,headers=headers,timeout=min(settings.request_timeout,10));r.raise_for_status();payload=r.json()
            if not isinstance(payload,(dict,list)):raise ValueError('Unexpected response type')
            result.update(status='CONNECTED',message=f'{NAMES[name]} connected; authentication accepted')
            if name=='sandbox':
                if settings.sandbox_kind=='cuckoo3':
                    from .providers import windows_available
                    ready=windows_available(payload)
                    result['available_platforms']=payload
                else:ready=bool(payload.get('machines',{}).get('available',0) or payload.get('data',{}).get('machines',{}).get('available',0))
                result.update(execution_ready=ready and settings.sandbox_isolation_confirmed,isolation_confirmed=settings.sandbox_isolation_confirmed)
                if not ready:result.update(status='NO_ANALYSIS_MACHINE',message='Cuckoo API connected, but no matching Windows analysis machine is available')
                elif not settings.sandbox_isolation_confirmed:result.update(status='ISOLATION_REQUIRED',message='Cuckoo API connected; VM isolation and snapshot restoration must be verified before execution')
        except Exception as e:
            detail=diagnostic(name,e);result.update(status=detail['code'],message=detail['message'],retry_after_seconds=detail['retry_after_seconds'])
            # The pinned Cuckoo API raises HTTP 500 for platform discovery
            # until core has generated its first node inventory. Distinguish
            # an authenticated API with no scheduler from bad credentials.
            if name=='sandbox' and settings.sandbox_kind=='cuckoo3' and isinstance(e,httpx.HTTPStatusError) and e.response.status_code>=500:
                try:
                    probe=httpx.get(settings.cuckoo_api_url.rstrip('/')+'/analyses/',headers={'Authorization':'Token '+key},timeout=min(settings.request_timeout,10))
                    probe.raise_for_status()
                    if isinstance(probe.json().get('analyses'),list):
                        result.update(status='CORE_NOT_READY',message='Cuckoo API authenticated, but core has not supplied a usable machine inventory. Check Cuckoo core logs and host/VM prerequisites.')
                except Exception:pass
        result['checked_at']=datetime.now(timezone.utc).isoformat()
    with _LOCK:_CACHE[identity]=(time.monotonic(),result)
    return result
