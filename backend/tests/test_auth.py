import pytest
from fastapi import HTTPException
from app.auth import token,require_user
from app.config import settings

def test_signed_session_rejects_tampering(monkeypatch):
    monkeypatch.setattr(settings,'auth_secret','test-signing-key'*4)
    cookie=token(settings.admin_username)
    assert require_user(cookie)==settings.admin_username
    with pytest.raises(HTTPException): require_user(cookie+'0')
    with pytest.raises(HTTPException): require_user(None)

def test_signing_key_rotation_invalidates_sessions(monkeypatch):
    monkeypatch.setattr(settings,'auth_secret','old'*20)
    cookie=token(settings.admin_username)
    monkeypatch.setattr(settings,'auth_secret','new'*20)
    with pytest.raises(HTTPException): require_user(cookie)
