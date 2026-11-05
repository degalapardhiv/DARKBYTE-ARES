from __future__ import annotations

import secrets
import warnings
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed application settings.

    Safety-critical limits live here and are validated at boot. The development
    defaults are deliberately conservative; deployments must override secrets.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "DARKBYTE ARES"
    app_env: str = "development"
    debug: bool = False
    demo_mode: bool = True
    allow_registration: bool = True
    secret_key: str = "development-only-change-me-please"
    access_token_expire_minutes: int = Field(default=480, ge=5, le=1440)
    allowed_origins: str = "http://localhost:5173,http://localhost:8080"

    database_url: str = "sqlite+aiosqlite:///./data/ares.db"
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = Field(default=900, ge=30, le=86400)

    admin_email: str = "admin@ares.example.com"
    admin_password: str = "Ares!Admin2026"
    analyst_email: str = "analyst@ares.example.com"
    analyst_password: str = "Ares!Analyst2026"

    max_scan_hosts: int = Field(default=64, ge=1, le=256)
    max_ports_per_scan: int = Field(default=512, ge=1, le=2048)
    scan_timeout_seconds: float = Field(default=4.0, ge=0.5, le=30.0)
    max_concurrent_assessments: int = Field(default=2, ge=1, le=8)
    assessment_timeout_seconds: int = Field(default=180, ge=15, le=900)
    rate_limit_per_minute: int = Field(default=120, ge=10, le=10000)
    active_scan_rate_limit: int = Field(default=30, ge=2, le=1000)
    require_verified_targets: bool = True
    allow_private_targets: bool = True
    allow_loopback_lab: bool = True

    nvd_api_key: str = ""
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    mitre_attack_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    crtsh_url: str = "https://crt.sh/"
    reports_dir: str = "./data/reports"
    lab_mode: bool = True

    @field_validator("app_env")
    @classmethod
    def _known_environment(cls, value: str) -> str:
        value = value.lower()
        if value not in {"development", "test", "staging", "production"}:
            raise ValueError("app_env must be development, test, staging, or production")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def secure_secret(self) -> bool:
        weak = {
            "development-only-change-me-please",
            "change-me-to-a-random-64-character-secret",
            "secret",
            "",
        }
        return len(self.secret_key) >= 32 and self.secret_key not in weak

    def validate_runtime_safety(self) -> None:
        if self.is_production:
            if not self.secure_secret:
                raise RuntimeError(
                    "SECRET_KEY must be a unique value of at least 32 characters in production."
                )
            if self.demo_mode:
                raise RuntimeError("DEMO_MODE must be disabled in production.")
            if "*" in self.origins:
                raise RuntimeError("Wildcard CORS origins are not allowed in production.")
        elif not self.secure_secret:
            warnings.warn(
                "Using an insecure development SECRET_KEY. Set SECRET_KEY before deployment.",
                RuntimeWarning,
                stacklevel=2,
            )
        if self.max_scan_hosts > 256:
            raise RuntimeError("MAX_SCAN_HOSTS exceeds the hard safety ceiling (256).")

    def ensure_directories(self) -> None:
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite"):
            raw = self.database_url.split("///", 1)[-1]
            if raw and raw != ":memory:":
                Path(raw).parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_runtime_safety()
    settings.ensure_directories()
    return settings


def generate_secret() -> str:
    return secrets.token_urlsafe(48)
