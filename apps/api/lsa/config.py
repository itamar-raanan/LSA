from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LSA_", env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./lsa.sqlite3"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    session_secret: str = "development-session-secret-change-in-production"
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
