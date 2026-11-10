import httpx
import pytest
from app import sandbox_cleanup
from app.config import settings

SHA='a'*64

@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setattr(settings,'cuckoo_api_url','https://sandbox.example/api')
    monkeypatch.setattr(settings,'cuckoo_api_token','fixture-token')
    monkeypatch.setattr(settings,'sandbox_kind','cuckoo3')
    real=httpx.Client
    def configure(handler):
        monkeypatch.setattr(sandbox_cleanup.httpx,'Client',lambda **kw:real(transport=httpx.MockTransport(handler),**kw))
    return configure


def test_cuckoo3_delete_checks_identity_hash_and_terminal_state(remote):
    calls=[]
    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith('/deleteanalysis'): return httpx.Response(200)
        if len(calls)==3:return httpx.Response(404)
        return httpx.Response(200,json={'id':'20261101-ABCDEF','state':'finished',
            'submitted':{'sha256':SHA},'tasks':[{'state':'reported'}]})
    remote(handler)
    sandbox_cleanup.delete_analysis({'task_id':'20261101-ABCDEF','provider':'cuckoo3'},SHA)
    assert calls==['/api/analysis/20261101-ABCDEF','/api/analysis/20261101-ABCDEF/deleteanalysis','/api/analysis/20261101-ABCDEF']


@pytest.mark.parametrize('state',['tasks_pending','pending_pre','waiting_manual','unknown'])
def test_cuckoo3_never_deletes_nonterminal_tasks(remote,state):
    def handler(request):
        assert not request.url.path.endswith('/deleteanalysis')
        return httpx.Response(200,json={'id':'20261101-ABCDEF','state':state,'submitted':{'sha256':SHA}})
    remote(handler)
    with pytest.raises(sandbox_cleanup.SandboxStillActive):
        sandbox_cleanup.delete_analysis({'task_id':'20261101-ABCDEF','provider':'cuckoo3'},SHA)


@pytest.mark.parametrize('kind',['cape','cuckoo'])
def test_legacy_and_cape_routes(remote,monkeypatch,kind):
    monkeypatch.setattr(settings,'sandbox_kind',kind)
    paths=[]
    def handler(request):
        paths.append(request.url.path)
        if '/delete/' in request.url.path: return httpx.Response(200,json={'error':False})
        if len(paths)==3:return httpx.Response(404)
        return httpx.Response(200,json={'data' if kind=='cape' else 'task':{'id':42,'status':'reported','sample':{'sha256':SHA}}})
    remote(handler)
    sandbox_cleanup.delete_analysis({'task_id':42,'source':kind},SHA)
    slash='/' if kind=='cape' else ''
    assert paths==['/api/tasks/view/42'+slash,'/api/tasks/delete/42'+slash,'/api/tasks/view/42'+slash]


def test_success_response_without_actual_deletion_is_retried(remote):
    def handler(request):
        if request.url.path.endswith('/deleteanalysis'):return httpx.Response(200)
        return httpx.Response(200,json={'id':'20261101-ABCDEF','state':'finished','submitted':{'sha256':SHA}})
    remote(handler)
    with pytest.raises(RuntimeError,match='not confirmed'):
        sandbox_cleanup.delete_analysis({'task_id':'20261101-ABCDEF','provider':'cuckoo3'},SHA)


@pytest.mark.parametrize('failure',['hash','endpoint','permissions','transport'])
def test_remote_errors_preserve_cleanup_inventory(remote,failure):
    def handler(request):
        assert not request.url.path.endswith('/deleteanalysis')
        if failure=='permissions': return httpx.Response(403)
        if failure=='transport': raise httpx.ConnectError('offline')
        return httpx.Response(200,json={'id':'20261101-ABCDEF','state':'finished','submitted':{'sha256':'b'*64}})
    remote(handler)
    data={'task_id':'20261101-ABCDEF','provider':'cuckoo3'}
    if failure=='endpoint': data['endpoint_identity']='old-instance'
    with pytest.raises((ValueError,RuntimeError,httpx.HTTPError)):
        sandbox_cleanup.delete_analysis(data,SHA)


def test_remote_missing_task_is_idempotent(remote):
    remote(lambda request:httpx.Response(404))
    sandbox_cleanup.delete_analysis({'task_id':'20261101-ABCDEF','provider':'cuckoo3'},SHA)


def test_cape_error_body_is_not_success(remote,monkeypatch):
    monkeypatch.setattr(settings,'sandbox_kind','cape')
    remote(lambda request:httpx.Response(200,json={'error':True,'error_value':'Task View API is Disabled'}))
    with pytest.raises(RuntimeError): sandbox_cleanup.delete_analysis({'task_id':42,'provider':'cape'},SHA)


def test_unknown_submission_outcome_is_retained_for_reconciliation():
    with pytest.raises(RuntimeError): sandbox_cleanup.delete_analysis({'phase':'submission_pending'},SHA)


def test_missing_deletion_route_is_not_treated_as_deleted(remote):
    def handler(request):
        if request.url.path.endswith('/deleteanalysis'): return httpx.Response(404)
        return httpx.Response(200,json={'id':'20261101-ABCDEF','state':'finished','submitted':{'sha256':SHA}})
    remote(handler)
    with pytest.raises(RuntimeError):
        sandbox_cleanup.delete_analysis({'task_id':'20261101-ABCDEF','provider':'cuckoo3'},SHA)
