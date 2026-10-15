"""Contract tests with explicit HTTP fixtures; real network is never used here."""
import httpx
import pytest
from app import providers
from app.config import settings

def use_transport(monkeypatch,handler):
    original=httpx.Client
    monkeypatch.setattr(providers.httpx,'Client',lambda **kw:original(transport=httpx.MockTransport(handler),**kw))

def test_vt_no_upload_without_both_gates(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','test-key')
    monkeypatch.setattr(settings,'external_uploads_enabled',False)
    calls=[]
    def handler(r): calls.append(r.method);return httpx.Response(404)
    use_transport(monkeypatch,handler)
    with pytest.raises(providers.Unavailable): providers.virustotal(b'test','a'*64,True)
    assert calls==['GET']

def test_vt_actual_response_normalization(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','test-key')
    def handler(r):
        assert r.headers['x-apikey']=='test-key'
        return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':7,'undetected':3},'last_analysis_results':{'TestAV':{'category':'malicious','result':'test-signature'}}}}})
    use_transport(monkeypatch,handler)
    result=providers.virustotal(b'', 'b'*64,False)
    assert result['total']==10 and result['stats']['malicious']==7
    assert result['engines']['TestAV']['result']=='test-signature'

def test_hybrid_does_not_submit_without_consent(monkeypatch):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    monkeypatch.setattr(settings,'external_uploads_enabled',True)
    methods=[]
    def handler(r):
        assert r.url.host=='hybrid-analysis.com'
        assert r.headers['api-key']=='test-key'
        methods.append(r.method)
        return httpx.Response(200,json=[])
    use_transport(monkeypatch,handler)
    with pytest.raises(providers.Unavailable): providers.hybrid(b'test','a'*64,False)
    assert methods==['GET']

def test_provider_rate_limit_is_error(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','test-key')
    use_transport(monkeypatch,lambda r:httpx.Response(429))
    with pytest.raises(httpx.HTTPStatusError): providers.virustotal(b'', 'a'*64,False)

def test_sandbox_requires_isolation_attestation(monkeypatch):
    monkeypatch.setattr(settings,'cuckoo_api_url','http://sandbox.invalid/apiv2')
    monkeypatch.setattr(settings,'sandbox_isolation_confirmed',False)
    with pytest.raises(providers.Unavailable): providers.CuckooCapeProvider()

@pytest.mark.parametrize('enabled,consent',[(False,False),(True,False),(False,True)])
def test_hybrid_missing_hash_404_respects_both_consent_gates(monkeypatch,enabled,consent):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    monkeypatch.setattr(settings,'external_uploads_enabled',enabled)
    calls=[]
    def handler(r):
        calls.append(r.method)
        return httpx.Response(404,json={'message':'Requested hash not found'})
    use_transport(monkeypatch,handler)
    with pytest.raises(providers.Unavailable,match='No existing Hybrid Analysis report'):
        providers.hybrid(b'sample','a'*64,consent)
    assert calls==['GET']

def test_hybrid_unrelated_404_is_not_hidden(monkeypatch):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    use_transport(monkeypatch,lambda r:httpx.Response(404,json={'message':'Route not found'}))
    with pytest.raises(httpx.HTTPStatusError):providers.hybrid(b'','a'*64,False)

def test_hybrid_current_wrapper_and_id(monkeypatch):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    paths=[]
    def handler(r):
        paths.append(r.url.path)
        if r.url.path.endswith('/search/hash'):
            return httpx.Response(200,json={'sha256s':['a'*64],'reports':[{'id':'failed-report','state':'ERROR'},{'id':'good-report','state':'SUCCESS'}]})
        if r.url.path.endswith('/file/json'):
            return httpx.Response(403,json={'message':'Full report download not permitted'})
        assert r.url.path.endswith('/report/good-report/summary')
        return httpx.Response(200,json={'state':'SUCCESS','sha256':'a'*64,'verdict':'suspicious','threat_score':40})
    use_transport(monkeypatch,handler)
    r=providers.hybrid(b'','a'*64,False)
    assert r['task_id']=='good-report' and r['verdict']=='suspicious'
    assert len(paths)==3
    assert r['raw_responses']['summary']['threat_score']==40
    assert r['raw_responses']['full_report_access']['code']=='ACCESS_DENIED'

def test_hybrid_error_report_never_completes(monkeypatch):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    def handler(r):
        if r.url.path.endswith('/search/hash'):return httpx.Response(200,json={'reports':[{'id':'bad','state':'ERROR'}]})
        return httpx.Response(200,json={'state':'ERROR','verdict':'no specific threat'})
    use_transport(monkeypatch,handler)
    with pytest.raises(providers.ProviderFailure,match='execution failed'):providers.hybrid(b'','a'*64,False)

def test_hybrid_missing_hash_can_submit_with_both_gates(monkeypatch):
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','test-key')
    monkeypatch.setattr(settings,'external_uploads_enabled',True)
    calls=[]
    def handler(r):
        calls.append(r.method)
        if r.url.path.endswith('/search/hash'):return httpx.Response(404,json={'message':'Requested hash not found'})
        if r.url.path.endswith('/submit/file'):return httpx.Response(200,json={'job_id':'new-task'})
        return httpx.Response(200,json={'state':'SUCCESS','sha256':'a'*64,'verdict':'no specific threat'})
    use_transport(monkeypatch,handler)
    r=providers.hybrid(b'consented test file','a'*64,True)
    assert r['task_id']=='new-task' and calls==['GET','POST','GET','GET','GET']
