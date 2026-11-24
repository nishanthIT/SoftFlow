"""Authentication requests use valid HTTP headers and keep failures operator-only."""
import h11
import httpx
import pytest
from app import provider_status, providers, sandbox_cleanup
from app.config import settings


@pytest.fixture(autouse=True)
def classic(monkeypatch):
    monkeypatch.setattr(settings,'sandbox_enabled',True)
    monkeypatch.setattr(settings,'presentation_mode',False)
    monkeypatch.setattr(settings,'sandbox_kind','cuckoo')
    monkeypatch.setattr(settings,'sandbox_isolation_confirmed',True)
    monkeypatch.setattr(settings,'cuckoo_api_url','http://sandbox.invalid:8090')
    monkeypatch.setattr(settings,'cuckoo_api_token','')


def validate_http(request):
    try:
        h11.Request(method=request.method,target=request.url.raw_path,headers=request.headers.raw)
    except h11.LocalProtocolError as error:
        raise httpx.LocalProtocolError('Invalid HTTP request header',request=request) from error


def test_missing_token_reaches_server_without_blank_bearer(monkeypatch):
    requests=[]
    def get(url,**kwargs):
        request=httpx.Request('GET',url,headers=kwargs['headers'])
        validate_http(request);requests.append(request)
        return httpx.Response(401,request=request)
    monkeypatch.setattr(httpx,'get',get)
    result=provider_status.check('sandbox',refresh=True)
    assert result['status']=='API_TOKEN_REQUIRED'
    assert len(requests)==1 and 'authorization' not in requests[0].headers
    assert result['execution_ready'] is False and 'CUCKOO_CWD' in result['message']


def test_classic_server_without_auth_still_works(monkeypatch):
    def get(url,**kwargs):
        request=httpx.Request('GET',url,headers=kwargs['headers']);validate_http(request)
        assert 'authorization' not in request.headers
        body={'machines':[{'platform':'windows'}]} if url.endswith('/machines/list') else {'processes':{'cuckoo':[42]}}
        return httpx.Response(200,json=body,request=request)
    monkeypatch.setattr(httpx,'get',get)
    assert provider_status.check('sandbox',refresh=True)['execution_ready'] is True


def test_bad_nonempty_token_remains_an_auth_failure(monkeypatch):
    monkeypatch.setattr(settings,'cuckoo_api_token','wrong-fixture-token')
    def get(url,**kwargs):
        assert kwargs['headers']=={'Authorization':'Bearer wrong-fixture-token'}
        return httpx.Response(401,request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx,'get',get)
    result=provider_status.check('sandbox',refresh=True)
    assert result['status']=='INVALID_API_KEY'
    assert 'wrong-fixture-token' not in str(result)


def test_cuckoo3_missing_token_does_not_send_request(monkeypatch):
    monkeypatch.setattr(settings,'sandbox_kind','cuckoo3')
    monkeypatch.setattr(httpx,'get',lambda *a,**kw:pytest.fail('Cuckoo 3 requires a token'))
    assert provider_status.check('sandbox',refresh=True)['status']=='API_TOKEN_REQUIRED'


@pytest.mark.parametrize('token',['bad\r\nHeader:value','bad token','non-ascii-\u00e9'])
def test_malformed_token_is_configuration_failure(monkeypatch,token):
    monkeypatch.setattr(settings,'cuckoo_api_token',token)
    monkeypatch.setattr(httpx,'get',lambda *a,**kw:pytest.fail('Invalid token must not be sent'))
    result=provider_status.check('sandbox',refresh=True)
    assert result['status']=='INVALID_API_TOKEN'
    assert token not in str(result)


def test_legacy_provider_omits_empty_auth_header(monkeypatch):
    real=httpx.Client
    def handler(request):
        validate_http(request)
        assert 'authorization' not in request.headers
        return httpx.Response(401)
    monkeypatch.setattr(httpx,'Client',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    provider=providers.CuckooCapeProvider()
    try:
        with pytest.raises(httpx.HTTPStatusError):provider.get_status(1)
    finally:provider.client.close()


def test_cleanup_missing_auth_keeps_upstream_record(monkeypatch):
    real=httpx.Client;requests=[]
    def handler(request):
        validate_http(request);requests.append(request)
        assert 'authorization' not in request.headers and '/delete/' not in request.url.path
        return httpx.Response(401)
    monkeypatch.setattr(httpx,'Client',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    with pytest.raises(httpx.HTTPStatusError):
        sandbox_cleanup.delete_analysis({'task_id':1,'source':'cuckoo'},'a'*64)
    assert len(requests)==1
