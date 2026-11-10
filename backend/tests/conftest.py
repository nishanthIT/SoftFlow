"""Isolate tests from the workstation's runtime and sandbox settings."""
import pytest
from app.config import settings

@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.setattr(settings,'app_env','development')
    monkeypatch.setattr(settings,'sandbox_enabled',True)
