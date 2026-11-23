"""Environment-based configuration.

All settings are read from environment variables prefixed with ``VIBESCAN_`` (or a ``.env`` file).
Production refuses to start with insecure defaults.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

INSECURE_DEV_SECRET = "dev-insecure-secret-change-me-0123456789abcdef"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIBESCAN_", env_file=".env", extra="ignore")

    environment: Literal["development", "production", "test"] = "development"
    secret_key: str = INSECURE_DEV_SECRET

    database_url: str = "sqlite+aiosqlite:///./data/vibescan.db"
    redis_url: str = "redis://localhost:6379/0"
    task_backend: Literal["inline", "arq"] = "inline"

    # Operator sessions
    session_ttl_hours: int = 12
    cookie_secure: bool | None = None  # defaults to True in production
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    # Target authorization
    verification_validity_days: int = 30
    lab_mode: bool = False
    allow_attestation_only: bool = False
    auto_verify_targets: bool = False
    allow_private_targets: bool = False
    private_target_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Scanner limits
    default_scan_timeout_seconds: int = 900
    max_scan_timeout_seconds: int = 7200
    max_requests_per_scan: int = 25000
    max_response_bytes: int = 5 * 1024 * 1024
    max_pages_hard_limit: int = 5000
    max_rps_hard_limit: float = 100.0
    max_concurrency_hard_limit: int = 50
    user_agent: str = "VibeScan/0.1 (authorized security assessment; non-destructive)"

    # Storage
    data_dir: Path = Path("./data")
    max_upload_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 300 * 1024 * 1024
    max_archive_files: int = 20000
    max_source_file_bytes: int = 2 * 1024 * 1024

    # AI analyst
    ai_provider: Literal["openai", "disabled"] = "disabled"
    ai_model: str = "gpt-4o-mini"
    ai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str | None = None
    ai_timeout_seconds: int = 90
    ai_auto_analyze: bool = False

    # Bootstrap
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    semgrep_binary: str = "semgrep"
    semgrep_timeout_seconds: int = 300

    @field_validator("private_target_allowlist", mode="before")
    @classmethod
    def _split_cidrs(cls, v: object) -> object:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @field_validator("private_target_allowlist")
    @classmethod
    def _validate_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            ipaddress.ip_network(cidr, strict=False)
        return v

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        if self.environment == "production":
            if self.secret_key == INSECURE_DEV_SECRET or len(self.secret_key) < 32:
                raise ValueError("VIBESCAN_SECRET_KEY must be set to a random value of >= 32 chars in production")
            if self.allow_attestation_only and not self.lab_mode:
                raise ValueError("allow_attestation_only requires lab_mode")
            if self.auto_verify_targets and not self.lab_mode:
                raise ValueError("auto_verify_targets requires lab_mode in production")
        if self.allow_private_targets and not self.private_target_allowlist:
            raise ValueError("allow_private_targets requires an explicit VIBESCAN_PRIVATE_TARGET_ALLOWLIST")
        return self

    @property
    def secure_cookies(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.environment == "production"

    @property
    def private_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(c, strict=False) for c in self.private_target_allowlist]

    @property
    def attestation_allowed(self) -> bool:
        return self.lab_mode and self.allow_attestation_only

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


@lru_cache
def get_settings() -> Settings:
    return Settings()
