"""Application configuration loaded from environment variables."""

from enum import StrEnum

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_MAX_REPORT_UPLOAD_BYTES = 25 * 1024 * 1024


class Environment(StrEnum):
    """Supported runtime environments for the application."""

    LOCAL = "local"
    TEST = "test"
    PRODUCTION = "production"


class AppSettings(BaseSettings):
    """Typed settings for application, database, session, and storage behavior."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="DIONYSUS_",
        extra="ignore",
    )

    environment: Environment = Environment.LOCAL
    database_url: str = "sqlite:///./var/dionysus.db"
    session_idle_timeout_minutes: int = Field(default=30, ge=1)
    session_absolute_timeout_minutes: int = Field(default=480, ge=1)
    machine_access_token_expires_minutes: int = Field(default=15, ge=1)
    machine_refresh_token_expires_minutes: int = Field(default=60, ge=1)
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_admin_display_name: str | None = None
    raw_report_storage_backend: str = "none"
    raw_report_retention_days: int = Field(default=0, ge=0)
    max_report_upload_bytes: int = Field(default=DEFAULT_MAX_REPORT_UPLOAD_BYTES, ge=1)
