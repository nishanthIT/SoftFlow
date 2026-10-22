"""Cuckoo 3 source-contract fixtures. These are not live VM verification."""
import hashlib
import json
import httpx
import pytest
from app import providers, policy
from app.config import settings
from app.provider_status import check

ANALYSIS = '20261015-ABC123'
TASK = ANALYSIS + '_1'
DATA = b'contract fixture, never executed'


@pytest.fixture
def sandbox(monkeypatch):
    monkeypatch.setattr(settings, 'sandbox_kind', 'cuckoo3')
    monkeypatch.setattr(settings, 'cuckoo_api_url', 'http://cuckoo.invalid')
    monkeypatch.setattr(settings, 'cuckoo_api_token', 'contract-test-token')
    monkeypatch.setattr(settings, 'sandbox_isolation_confirmed', True)
    monkeypatch.setattr(settings, 'sandbox_os_version', '10')
    monkeypatch.setattr(providers.time, 'sleep', lambda _: None)
    return {
        '/submit/platforms': {'windows': ['10']},
        '/submit/file': {'analysis_id': ANALYSIS},
        '/analysis/' + ANALYSIS: {'id': ANALYSIS, 'state': 'finished', 'errors': {},
                                 'submitted': {'sha256': hashlib.sha256(DATA).hexdigest()}, 'tasks': [{'id': TASK}]},
        f'/analysis/{ANALYSIS}/task/{TASK}': {'id': TASK, 'analysis_id': ANALYSIS, 'state': 'reported', 'errors': {}},
        f'/analysis/{ANALYSIS}/task/{TASK}/post': {'task_id': TASK,
            'processes': [{'name': 'fixture.exe', 'pid': 4, 'image': 'fixture.exe', 'start_ts': 12}],
            'signatures': [], 'network': {'dns': {'query': [{'name': 'test.example', 'type': 'A', 'ts': 10}]},
            'http': [{'request': {'url': 'https://test.example/check', 'protocol': 'https', 'method': 'GET'}, 'dstip': '192.0.2.1', 'dstport': 443}],
            'tcp': [{'dstip': '192.0.2.1', 'dstport': 443}]}}
    }


def transport(monkeypatch, responses):
    calls = []
    original = httpx.Client
    def handler(request):
        calls.append(request)
        assert request.headers['Authorization'] == 'Token contract-test-token'
        value = responses[request.url.path]
        if callable(value): return value(request)
        return httpx.Response(200, json=value)
    monkeypatch.setattr(providers.httpx, 'Client', lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    return calls


def test_success_hash_filename_and_cuckoo3_normalization(monkeypatch, sandbox):
    calls = transport(monkeypatch, sandbox)
    saved = []
    result = providers.Cuckoo3Provider().run(DATA, saved.append, filename='original.exe')
    post = next(r for r in calls if r.method == 'POST')
    assert b'filename="original.exe"' in post.content
    assert b'"enforce_timeout": true' in post.content
    assert result['task_id'] == ANALYSIS and result['phase'] == 'reported'
    assert saved[1]['phase'] == 'submission_pending'
    assert policy.behavior(result)['processes'][0]['process_name'] == 'fixture.exe'
    network = policy.network(result)
    assert network['domains'] == ['test.example'] and network['ips'] == ['192.0.2.1']
    assert network['events'][1]['type'] == 'https'


def test_resume_never_posts(monkeypatch, sandbox):
    calls = transport(monkeypatch, sandbox)
    providers.Cuckoo3Provider().run(DATA, lambda _: None, {'task_id': ANALYSIS})
    assert all(r.method == 'GET' for r in calls)


def test_crash_during_submission_not_blindly_retried(monkeypatch, sandbox):
    calls = transport(monkeypatch, sandbox)
    with pytest.raises(providers.ProviderFailure, match='outcome is unknown'):
        providers.Cuckoo3Provider().run(DATA, lambda _: None, {'phase': 'submission_pending'})
    assert not calls


def test_scheduler_503_retains_persisted_id(monkeypatch, sandbox):
    sandbox['/submit/file'] = lambda _: httpx.Response(503, json={'analysis_id': ANALYSIS, 'error': 'scheduler offline'})
    calls = transport(monkeypatch, sandbox); saved = []
    with pytest.raises(providers.Unavailable, match='scheduler'):
        providers.Cuckoo3Provider().run(DATA, saved.append)
    assert saved[-1]['task_id'] == ANALYSIS
    assert len([r for r in calls if r.method == 'POST']) == 1


@pytest.mark.parametrize('state', ['fatal_error', 'no_selected', 'waiting_manual'])
def test_terminal_failures_stop_immediately(monkeypatch, sandbox, state):
    sandbox['/analysis/' + ANALYSIS]['state'] = state
    calls = transport(monkeypatch, sandbox); saved = []
    with pytest.raises(providers.ProviderFailure, match=state):
        providers.Cuckoo3Provider().run(DATA, saved.append)
    assert saved[-1]['raw_analysis']['state'] == state
    assert len(calls) == 3


def test_failed_task_preserved_without_fetching_missing_post(monkeypatch, sandbox):
    sandbox[f'/analysis/{ANALYSIS}/task/{TASK}'].update(state='fatal_error', errors={'fatal': ['guest agent failed']})
    calls = transport(monkeypatch, sandbox); saved = []
    with pytest.raises(providers.ProviderFailure, match='task failed'):
        providers.Cuckoo3Provider().run(DATA, saved.append)
    assert saved[-1]['report']['tasks'][0]['task']['errors']['fatal']
    assert not any(r.url.path.endswith('/post') for r in calls)


@pytest.mark.parametrize('hash_value', ['', 'f' * 64])
def test_missing_or_wrong_hash_fails(monkeypatch, sandbox, hash_value):
    sandbox['/analysis/' + ANALYSIS]['submitted']['sha256'] = hash_value
    transport(monkeypatch, sandbox)
    with pytest.raises(providers.ProviderFailure, match='hash'):
        providers.Cuckoo3Provider().run(DATA, lambda _: None)


@pytest.mark.parametrize('platforms', [{}, {'linux': ['22.04']}, {'windows': ['7']}])
def test_matching_machine_required(monkeypatch, sandbox, platforms):
    sandbox['/submit/platforms'] = platforms
    calls = transport(monkeypatch, sandbox)
    with pytest.raises(providers.Unavailable, match='matching Windows'):
        providers.Cuckoo3Provider().run(DATA, lambda _: None)
    assert len(calls) == 1


@pytest.mark.parametrize('status', [401, 403])
def test_authentication_errors_are_not_retried(monkeypatch, sandbox, status):
    sandbox['/submit/platforms'] = lambda _: httpx.Response(status)
    calls = transport(monkeypatch, sandbox)
    with pytest.raises(httpx.HTTPStatusError): providers.Cuckoo3Provider().run(DATA, lambda _: None)
    assert len(calls) == 1


def test_late_report_and_transient_read_recover(monkeypatch, sandbox):
    path = f'/analysis/{ANALYSIS}/task/{TASK}/post'; post = sandbox[path]; attempt = []
    def late(_):
        attempt.append(1)
        return httpx.Response(503 if len(attempt) == 1 else 404) if len(attempt) < 3 else httpx.Response(200, json=post)
    sandbox[path] = late
    transport(monkeypatch, sandbox)
    assert providers.Cuckoo3Provider().run(DATA, lambda _: None)['phase'] == 'reported'
    assert len(attempt) == 3


def test_expired_checkpoint_does_not_restart_deadline(monkeypatch, sandbox):
    calls = transport(monkeypatch, sandbox)
    with pytest.raises(providers.ProviderTimeout):
        providers.Cuckoo3Provider().run(DATA, lambda _: None, {'task_id': ANALYSIS, 'deadline_at': 1})
    assert not calls


def test_missing_telemetry_is_unavailable_but_empty_capture_is_valid(monkeypatch, sandbox):
    transport(monkeypatch, sandbox)
    result = providers.Cuckoo3Provider().run(DATA, lambda _: None)
    post = result['report']['tasks'][0]['post']
    post['network'] = {'dns': {'query': []}, 'tcp': []}
    assert policy.network(result)['events'] == []
    post.pop('network')
    assert policy.network(result) is None
    post['processes'] = []
    assert policy.behavior(result) is None


def test_health_checks_windows_version_and_cache_attestation(monkeypatch, sandbox):
    monkeypatch.setattr(httpx, 'get', lambda *a, **kw: httpx.Response(200, json={'windows': ['10']}, request=httpx.Request('GET', a[0])))
    assert check('sandbox', refresh=True)['execution_ready']
    monkeypatch.setattr(settings, 'sandbox_isolation_confirmed', False)
    assert not check('sandbox')['execution_ready']
