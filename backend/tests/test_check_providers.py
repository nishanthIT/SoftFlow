"""Regression for JSON .env values in the operator connectivity command."""
from pathlib import Path
import os
import pytest
from pydantic_settings import SettingsError
from app import check_providers
from app.config import Settings


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    root=Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root/'scripts'))
    # The CLI reads this temporary application directory, never workstation keys.
    monkeypatch.setattr(check_providers,'__file__',str(tmp_path/'backend/app/check_providers.py'))
    for key in list(os.environ):
        if key.lower() in Settings.model_fields or key.startswith('CUCKOO_'):
            monkeypatch.delenv(key)
    settings=Settings(_env_file=None)
    monkeypatch.setattr(check_providers,'settings',settings)
    cwd=tmp_path/'existing-cuckoo';(cwd/'conf').mkdir(parents=True)
    conf=cwd/'conf/cuckoo.conf';conf.write_text('[cuckoo]\napi_token = discovered-fixture-token\n')
    env=tmp_path/'.env'
    env.write_text('\n'.join([
        'CUCKOO_MODE=existing','SANDBOX_KIND=cuckoo',f'CUCKOO_CWD={cwd}',
        'CUCKOO_API_URL=http://127.0.0.1:8090','CUCKOO_API_TOKEN=',
        'SANDBOX_ENABLED=true','CUCKOO_AUTO_START=true',
        'SANDBOX_ISOLATION_CONFIRMED=true','API_PORT=8101',
        'ALLOWED_ORIGINS=["http://localhost:3100","http://127.0.0.1:3100"]',
        'POSTGRES_PASSWORD=unused-fixture-secret','VIRUSTOTAL_API_KEY=fixture-provider-key',
    ])+'\n')
    calls=[]
    def check(name,refresh=False):
        calls.append((name,refresh))
        return {'name':name,'status':'CONNECTED','message':'Fixture connectivity response'}
    monkeypatch.setattr(check_providers,'check',check)
    return env,conf,settings,calls


def test_json_origins_decoded_and_discovered_token_kept(runtime,capsys):
    env,conf,settings,calls=runtime
    before_env=env.read_bytes();before_conf=conf.read_bytes();environment=dict(os.environ)
    check_providers.main()
    assert settings.allowed_origins==['http://localhost:3100','http://127.0.0.1:3100']
    assert settings.cuckoo_api_token=='discovered-fixture-token'
    assert settings.sandbox_enabled is True and settings.cuckoo_auto_start is False
    assert settings.sandbox_isolation_confirmed is True and settings.api_port==8101
    assert calls==[('sandbox',True),('virustotal',True),('hybrid-analysis',True)]
    assert env.read_bytes()==before_env and conf.read_bytes()==before_conf and dict(os.environ)==environment
    output=capsys.readouterr().out
    assert 'No samples were submitted.' in output
    for secret in ('discovered-fixture-token','unused-fixture-secret','fixture-provider-key'):
        assert secret not in output


def test_environment_overrides_dotenv_without_losing_json_decoding(runtime,monkeypatch):
    _,_,settings,_=runtime
    monkeypatch.setenv('ALLOWED_ORIGINS','["http://server:3100"]')
    monkeypatch.setenv('API_PORT','8200')
    monkeypatch.setenv('CUCKOO_API_TOKEN','explicit-environment-token')
    check_providers.main()
    assert settings.allowed_origins==['http://server:3100'] and settings.api_port==8200
    assert settings.cuckoo_api_token=='explicit-environment-token'


def test_explicit_token_in_dotenv_is_preserved(runtime):
    env,_,settings,_=runtime
    env.write_text(env.read_text().replace('CUCKOO_API_TOKEN=\n','CUCKOO_API_TOKEN=explicit-dotenv-token\n'))
    check_providers.main()
    assert settings.cuckoo_api_token=='explicit-dotenv-token'


@pytest.mark.parametrize('origins',['[]','["http://localhost:3100"]'])
def test_json_origin_lists_remain_lists(runtime,origins):
    env,_,settings,_=runtime
    lines=[f'ALLOWED_ORIGINS={origins}' if line.startswith('ALLOWED_ORIGINS=') else line for line in env.read_text().splitlines()]
    env.write_text('\n'.join(lines)+'\n')
    check_providers.main()
    import json
    assert settings.allowed_origins==json.loads(origins)


def test_disabled_sandbox_stays_disabled(runtime):
    env,_,settings,_=runtime
    env.write_text(env.read_text().replace('SANDBOX_ENABLED=true','SANDBOX_ENABLED=false'))
    check_providers.main()
    assert settings.sandbox_enabled is False


def test_invalid_json_still_fails_validation(runtime):
    env,_,_,calls=runtime
    env.write_text(env.read_text()+'ALLOWED_ORIGINS=not-json\n')
    with pytest.raises(SettingsError):check_providers.main()
    assert calls==[]
