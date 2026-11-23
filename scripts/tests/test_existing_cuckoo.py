from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import existing_cuckoo as existing


@pytest.fixture(autouse=True)
def restore_settings():
    from app.config import settings
    saved=settings.model_dump()
    yield
    for key,value in saved.items():setattr(settings,key,value)


def test_existing_config_reuses_token_without_rewriting_config(tmp_path,monkeypatch):
    cwd=tmp_path/'my cuckoo';(cwd/'conf').mkdir(parents=True)
    conf=cwd/'conf/cuckoo.conf';content='[cuckoo]\napi_token = token-percent%value\n';conf.write_text(content)
    values={'CUCKOO_CWD':str(cwd)}
    monkeypatch.setattr(existing.shutil,'which',lambda _: '/opt/cuckoo/bin/cuckoo')
    existing.configure(values,tmp_path)
    assert values['CUCKOO_API_TOKEN']=='token-percent%value'
    assert values['CUCKOO_API_URL']=='http://127.0.0.1:8090'
    assert values['SANDBOX_KIND']=='cuckoo' and values['CUCKOO_AUTO_START']=='false'
    assert conf.read_text()==content


def test_child_environment_does_not_leak_app_keys(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','secret');monkeypatch.setenv('PYTHONPATH','/app')
    assert 'VIRUSTOTAL_API_KEY' not in existing.child_environment('/opt/cuckoo/bin/cuckoo')
    assert 'PYTHONPATH' not in existing.child_environment('/opt/cuckoo/bin/cuckoo')


def manager(tmp_path):
    calls=[]
    binary=tmp_path/'cuckoo';binary.touch()
    cwd=tmp_path/'cwd';(cwd/'conf').mkdir(parents=True);(cwd/'conf/cuckoo.conf').write_text('[cuckoo]')
    return SimpleNamespace(values={'CUCKOO_BINARY':str(binary),'CUCKOO_CWD':str(cwd),'SANDBOX_KIND':'cuckoo',
        'CUCKOO_API_URL':'http://127.0.0.1:8090','CUCKOO_API_TOKEN':'secret','SANDBOX_ISOLATION_CONFIRMED':'true'},
        message=lambda *a:None,start=lambda *a,**kw:calls.append(a),state={},alive=lambda _:True,calls=calls)


def test_reachable_existing_api_is_reused_without_launch(tmp_path,monkeypatch):
    from app import provider_status
    monkeypatch.setattr(provider_status,'check',lambda *a,**kw:{'status':'CONNECTED','execution_ready':True})
    m=manager(tmp_path)
    assert existing.start_existing(m)['execution_ready'] and not m.calls


def test_closed_local_port_launches_existing_classic_core_and_api(tmp_path,monkeypatch):
    from app import provider_status
    checks=iter([{'status':'NETWORK_UNAVAILABLE','execution_ready':False},{'status':'CONNECTED','execution_ready':True}])
    monkeypatch.setattr(provider_status,'check',lambda *a,**kw:next(checks))
    monkeypatch.setattr(existing.socket,'create_connection',lambda *a,**kw:(_ for _ in ()).throw(ConnectionRefusedError()))
    m=manager(tmp_path)
    assert existing.start_existing(m)['execution_ready']
    assert [c[0] for c in m.calls]==['cuckoo-core','cuckoo-api']
    assert m.calls[0][1]==[m.values['CUCKOO_BINARY'],'--cwd',m.values['CUCKOO_CWD']]


def test_remote_unreachable_api_does_not_launch_local_processes(tmp_path,monkeypatch):
    from app import provider_status
    monkeypatch.setattr(provider_status,'check',lambda *a,**kw:{'status':'NETWORK_UNAVAILABLE','execution_ready':False})
    m=manager(tmp_path);m.values['CUCKOO_API_URL']='https://sandbox.example'
    assert not existing.start_existing(m)['execution_ready'] and not m.calls


def test_api_with_stopped_core_restarts_core_only(tmp_path,monkeypatch):
    from app import provider_status
    checks=iter([{'status':'CORE_NOT_READY','execution_ready':False},{'status':'CONNECTED','execution_ready':True}])
    monkeypatch.setattr(provider_status,'check',lambda *a,**kw:next(checks))
    monkeypatch.setattr(existing.socket,'create_connection',lambda *a,**kw:pytest.fail('Do not probe an authenticated running API'))
    m=manager(tmp_path)
    assert existing.start_existing(m)['execution_ready']
    assert [c[0] for c in m.calls]==['cuckoo-core']


def test_discovers_kali_python27_environment_without_path_or_version_probe(tmp_path,monkeypatch):
    installed=tmp_path/'.venvs/cuckoo/bin/cuckoo';installed.parent.mkdir(parents=True);installed.touch()
    monkeypatch.setattr(existing.Path,'home',lambda:tmp_path)
    monkeypatch.setattr(existing.shutil,'which',lambda _:None)
    values={}
    existing.configure(values,tmp_path/'application')
    assert values['CUCKOO_BINARY']==str(installed)
    assert values['SANDBOX_KIND']=='cuckoo'
    assert values['CUCKOO_API_URL']=='http://127.0.0.1:8090'
