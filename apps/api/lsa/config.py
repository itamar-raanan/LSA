from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LSA_", env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./lsa.sqlite3"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    session_secret: str = "development-session-secret-change-in-production"
    settings_encryption_key: str | None = None
    session_ttl_minutes: int = 480
    bootstrap_email: str = "admin@lsa.local"
    bootstrap_password: str = "lsa-dev-password"
    seed_demo: bool = True
    max_upload_bytes: int = 25 * 1024 * 1024
    require_signed_bundles: bool = False
    artifact_backend: Literal["filesystem", "s3"] = "filesystem"
    artifact_path: str = "./artifacts"
    artifact_retention_days: int = Field(default=365, ge=0)
    s3_endpoint_url: str | None = None
    s3_bucket: str = "lsa-evidence"
    s3_region: str = "us-east-1"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_server_side_encryption: Literal["AES256", "aws:kms", "none"] = "AES256"
    public_url: str = "https://localhost:8443"
    agent_public_url: str = "https://localhost:8444"
    allow_private_identity_providers: bool = False
    tls_certificate_path: str = "/tmp/lsa-tls/tls.crt"
    tls_private_key_path: str = "/tmp/lsa-tls/tls.key"
    tls_shared_gid: int | None = None
    vulnerability_sync_enabled: bool = True
    vulnerability_refresh_hours: int = Field(default=12, ge=1, le=168)
    vulnerability_poll_seconds: int = Field(default=15, ge=2, le=300)
    vulnerability_http_timeout_seconds: int = Field(default=30, ge=5, le=120)
    vulnerability_http_retries: int = Field(default=3, ge=0, le=10)
    vulnerability_ca_bundle: str | None = None
    vulnerability_failure_retry_minutes: int = Field(default=15, ge=1, le=1440)
    vulnerability_run_timeout_minutes: int = Field(default=60, ge=10, le=1440)
    osv_api_url: str = "https://api.osv.dev"
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    @field_validator("agent_public_url")
    @classmethod
    def validate_agent_public_url(cls, value: str) -> str:
        normalized = value.rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path:
            raise ValueError("agent_public_url must be an HTTPS origin without a path")
        return normalized


@lru_cache
def get_settings() -> Settings:
    return Settings()
