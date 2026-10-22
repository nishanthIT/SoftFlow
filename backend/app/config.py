from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from pathlib import Path
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parents[2] / '.env', extra='ignore')
    database_url: str = 'postgresql+psycopg://sentinel:sentinel@postgres/sentinel'
    redis_url: str = 'redis://redis:6379/0'
    minio_endpoint: str = 'http://minio:9000'
    minio_access_key: str = ''
    minio_secret_key: str = ''
    storage_bucket: str = 'sentinel'
    storage_backend: Literal['minio', 's3', 'filesystem'] = 'minio'
    local_storage_path: str = str(Path(__file__).resolve().parents[2] / '.local/storage')
    allowed_origins: list[str] = []
    api_port: int = 8100
    frontend_port: int = 3100
    request_timeout: int = Field(30, ge=1, le=120)
    provider_poll_interval: int = Field(15, ge=1, le=60)
    provider_health_ttl: int = 60
    virustotal_api_key: str = ''
    hybrid_analysis_api_key: str = ''
    cuckoo_api_url: str = ''
    cuckoo_api_token: str = ''
    sandbox_kind: Literal['cape', 'cuckoo', 'cuckoo3'] = 'cape'
    sandbox_isolation_confirmed: bool = False
    sandbox_analysis_timeout: int = Field(120, ge=10, le=1200)
    sandbox_os_version: str = '10'
    sandbox_platform: Literal['windows'] = 'windows'
    external_uploads_enabled: bool = False
    max_upload_mb: int = 32
    provider_timeout: int = Field(900, ge=30, le=1800)
    hybrid_environment_id: int = 160
    approval_max_score: int = Field(0, ge=0, le=19)
    approval_reject_score: int = Field(60, ge=20, le=100)
    approval_min_reputation_engines: int = Field(20, ge=1)
    approval_require_reputation: bool = True
    yara_path: str = '/yara/rules'
    ai_signatures_path: str = '/ai-signatures/providers.json'
    mock_analysis: bool = False

settings = Settings()
