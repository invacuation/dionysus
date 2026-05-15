from pydantic_settings import SettingsConfigDict

from dionysus.config import AppSettings, Environment

SETTINGS_ENV_VARS = (
    "DIONYSUS_ENVIRONMENT",
    "DIONYSUS_DATABASE_URL",
    "DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES",
    "DIONYSUS_SESSION_ABSOLUTE_TIMEOUT_MINUTES",
    "DIONYSUS_MACHINE_ACCESS_TOKEN_EXPIRES_MINUTES",
    "DIONYSUS_MACHINE_REFRESH_TOKEN_EXPIRES_MINUTES",
    "DIONYSUS_RAW_REPORT_STORAGE_BACKEND",
    "DIONYSUS_RAW_REPORT_RETENTION_DAYS",
    "DIONYSUS_MAX_REPORT_UPLOAD_BYTES",
)


class DotenvFreeAppSettings(AppSettings):
    model_config = SettingsConfigDict(
        env_file=None,
        env_prefix="DIONYSUS_",
        extra="ignore",
    )


def clear_settings_environment(monkeypatch) -> None:
    for name in SETTINGS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_default_settings_use_local_sqlite(monkeypatch) -> None:
    clear_settings_environment(monkeypatch)

    settings = DotenvFreeAppSettings()

    assert settings.environment is Environment.LOCAL
    assert settings.database_url == "sqlite:///../var/dionysus.db"
    assert settings.session_idle_timeout_minutes == 30
    assert settings.session_absolute_timeout_minutes == 480
    assert settings.machine_access_token_expires_minutes == 15
    assert settings.machine_refresh_token_expires_minutes == 60
    assert settings.raw_report_storage_backend == "none"
    assert settings.raw_report_retention_days == 0
    assert settings.max_report_upload_bytes == 25 * 1024 * 1024


def test_settings_read_environment_variables(monkeypatch) -> None:
    clear_settings_environment(monkeypatch)
    monkeypatch.setenv("DIONYSUS_ENVIRONMENT", "test")
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", "sqlite:///./var/test.db")
    monkeypatch.setenv("DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES", "10")
    monkeypatch.setenv("DIONYSUS_SESSION_ABSOLUTE_TIMEOUT_MINUTES", "60")
    monkeypatch.setenv("DIONYSUS_MACHINE_ACCESS_TOKEN_EXPIRES_MINUTES", "5")
    monkeypatch.setenv("DIONYSUS_MACHINE_REFRESH_TOKEN_EXPIRES_MINUTES", "30")
    monkeypatch.setenv("DIONYSUS_RAW_REPORT_STORAGE_BACKEND", "local")
    monkeypatch.setenv("DIONYSUS_RAW_REPORT_RETENTION_DAYS", "7")
    monkeypatch.setenv("DIONYSUS_MAX_REPORT_UPLOAD_BYTES", "10485760")

    settings = DotenvFreeAppSettings()

    assert settings.environment is Environment.TEST
    assert settings.database_url == "sqlite:///./var/test.db"
    assert settings.session_idle_timeout_minutes == 10
    assert settings.session_absolute_timeout_minutes == 60
    assert settings.machine_access_token_expires_minutes == 5
    assert settings.machine_refresh_token_expires_minutes == 30
    assert settings.raw_report_storage_backend == "local"
    assert settings.raw_report_retention_days == 7
    assert settings.max_report_upload_bytes == 10 * 1024 * 1024
