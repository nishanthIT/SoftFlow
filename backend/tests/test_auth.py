"""The production LAN workspace is accessible without application authentication."""
from fastapi.testclient import TestClient
from sqlalchemy import select
from app import main
from app.config import settings
from app.models import User,Job
from test_api import client,pe


def test_production_access_without_credentials_preserves_history(client,monkeypatch):
    existing=client.post('/api/samples',files={'file':('earlier.exe',pe())}).json()['analysis_id']
    with main.Session.begin() as db:
        actor=User(username='historical-admin',role='workspace');db.add(actor);db.flush()
        old_actor=actor.id;db.get(Job,existing).user_id=actor.id
    monkeypatch.setattr(settings,'app_env','production')
    with TestClient(main.app) as direct:
        for path in ['/api/settings','/api/samples','/api/admin','/api/docs','/api/openapi.json']:
            reply=direct.get(path)
            assert reply.status_code==200,path
            assert 'set-cookie' not in reply.headers
        assert direct.get('/api/settings').json()['authentication_required'] is False
        uploaded=direct.post('/api/samples',files={'file':('new.exe',pe())})
        assert uploaded.status_code==201 and not direct.cookies
        identifier=uploaded.json()['analysis_id']
    with main.Session() as db:
        assert db.get(Job,existing).user_id==old_actor
        actor=db.get(User,db.get(Job,identifier).user_id)
        assert actor.username=='LAN workspace'


def test_auth_routes_are_removed_and_old_cookie_is_ignored(client):
    assert client.get('/api/auth/session').status_code==404
    assert client.post('/api/auth/login',json={'username':'admin','password':'unused'}).status_code==404
    assert client.post('/api/auth/logout').status_code==404
    client.cookies.set('sentinel_session','obsolete-session')
    assert client.get('/api/settings').status_code==200
