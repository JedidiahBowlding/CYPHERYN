from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PLATFORM_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = "development"
    database_url: str = "postgresql+psycopg://platform:platform@postgres:5432/platform"
    oidc_issuer: str = ""
    oidc_audience: str = "cypheryn"
    oidc_jwks_url: str = ""
    allow_dev_identity: bool = False
    cors_origins: list[str] = Field(default_factory=list)
    provider_encryption_key: str = ""
    local_ai_url: str = "http://127.0.0.1:11434"
    local_ai_model: str = "qwen2.5-coder:7b"
    local_ai_timeout_seconds: int = 120
    quarantine_dir: str = "../quarantine"
    local_import_root: str = "/var/lib/cypheryn/imports"
    malware_max_upload_bytes: int = 25 * 1024 * 1024
    clamav_database_dir: str = "../.runtime/clamav-db"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True
    integrity_anchor_enabled: bool = False
    integrity_anchor_key_dir: str = "/run/secrets/cypheryn-anchor"
    integrity_anchor_store_dir: str = "/anchors"
    integrity_anchor_interval_minutes: int = 1440
    federation_enabled: bool = False
    federation_display_name: str = "CYPHERYN Node"
    federation_key_path: str = "/run/secrets/cypheryn-federation/node.pem"
    federation_max_assertion_bytes: int = 64 * 1024
    federation_clock_skew_seconds: int = 300
    federation_rate_limit_per_minute: int = 60

    @model_validator(mode="after")
    def validate_authentication(self) -> "Settings":
        if self.environment.lower() == "production" and self.allow_dev_identity:
            raise ValueError("PLATFORM_ALLOW_DEV_IDENTITY cannot be enabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
