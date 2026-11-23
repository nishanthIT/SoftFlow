import httpx
import pytest
from app.provider_status import diagnostic,sanitize,check,_CACHE
from app.config import settings

@pytest.mark.parametrize('http_status,code',[(401,'INVALID_API_KEY'),(403,'ACCESS_DENIED'),(429,'RATE_LIMITED'),(404,'ANALYSIS_UNAVAILABLE'),(503,'API_UNAVAILABLE')])
def test_http_errors_are_distinct(http_status,code):
    r=httpx.Response(http_status,headers={'retry-after':'30'},request=httpx.Request('GET','https://provider.invalid'))
    try:r.raise_for_status()
    except httpx.HTTPStatusError as e:d=diagnostic('virustotal',e)
    assert d['code']==code
    assert 'VirusTotal' in d['message']
    if http_status==429:assert d['retry_after_seconds']==30

@pytest.mark.parametrize('error,code',[(httpx.ReadTimeout('sensitive URL'),'TIMEOUT'),(httpx.ConnectError('private details'),'NETWORK_UNAVAILABLE'),(ValueError('private response'),'INVALID_RESPONSE')])
def test_transport_errors_do_not_leak(error,code):
    d=diagnostic('hybrid-analysis',error)
    assert d['code']==code
    assert 'sensitive' not in str(d) and 'private' not in str(d)

def test_sanitize_nested_provider_and_sample_strings(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','sensitive-key-value')
    d=sanitize({'raw':{'extra_fields':['text sensitive-key-value content']}})
    assert d['raw']['extra_fields']==['text [REDACTED] content']

def test_health_invalid_key_not_connected(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','invalid-test-key')
    def get(*a,**kw):return httpx.Response(401,request=httpx.Request('GET','https://provider.invalid'))
    monkeypatch.setattr(httpx,'get',get)
    d=check('virustotal',refresh=True)
    assert d['configured'] and d['status']=='INVALID_API_KEY'
    assert 'invalid-test-key' not in str(d)

@pytest.mark.parametrize('machines,processes,expected',[
    ([],{'cuckoo':[123]},'NO_ANALYSIS_MACHINE'),
    ([{'platform':'linux'}],{'cuckoo':[123]},'NO_ANALYSIS_MACHINE'),
    ([{'platform':'windows','locked':True}],{'cuckoo':[123]},'CONNECTED'),
    ([{'platform':'windows'}],{},'CORE_NOT_READY'),
])
def test_classic_cuckoo_machine_inventory(monkeypatch,machines,processes,expected):
    monkeypatch.setattr(settings,'sandbox_kind','cuckoo')
    monkeypatch.setattr(settings,'cuckoo_api_url','http://localhost:8090')
    monkeypatch.setattr(settings,'sandbox_isolation_confirmed',True)
    def get(url,**kwargs):
        data={'machines':machines} if url.endswith('/machines/list') else {'machines':{'available':0},'processes':processes}
        return httpx.Response(200,json=data,request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx,'get',get)
    result=check('sandbox',refresh=True)
    assert result['status']==expected
    assert result['execution_ready']==(expected=='CONNECTED')
