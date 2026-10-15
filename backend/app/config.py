from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from pathlib import Path

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
    request_timeout: int = 30
    provider_poll_interval: int = 15
    provider_health_ttl: int = 60
    virustotal_api_key: str = ''
    hybrid_analysis_api_key: str = ''
    cuckoo_api_url: str = ''
    cuckoo_api_token: str = ''
    sandbox_kind: str = 'cape'
    sandbox_isolation_confirmed: bool = False
    external_uploads_enabled: bool = False
    max_upload_mb: int = 32
    provider_timeout: int = 900
    hybrid_environment_id: int = 160
    auth_secret: str = ''
    admin_username: str = 'admin'
    admin_password: str = ''
    secure_cookies: bool = True
    yara_path: str = '/yara/rules'
    ai_signatures_path: str = '/ai-signatures/providers.json'
    mock_analysis: bool = False

settings = Settings()
