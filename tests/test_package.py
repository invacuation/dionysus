from pathlib import Path

from dionysus import __version__
from dionysus.app import create_app
from dionysus.config import AppSettings, Environment

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_package_version() -> None:
    assert __version__ == (ROOT_DIR / ".VERSION").read_text(encoding="utf-8").strip()


def test_package_version_comes_from_root_version_file() -> None:
    assert __version__ == (ROOT_DIR / ".VERSION").read_text(encoding="utf-8").strip()


def test_create_app_sets_title() -> None:
    app = create_app(
        AppSettings(
            environment=Environment.TEST,
            database_url="sqlite:///:memory:",
            bootstrap_admin_username="admin",
            bootstrap_admin_password="change-me-now-please",  # noqa: S106 - test fixture password
        )
    )

    assert app.title == "Dionysus"
