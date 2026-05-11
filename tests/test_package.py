from pathlib import Path

from dionysus import __version__
from dionysus.app import create_app
from dionysus.config import AppSettings

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_package_version() -> None:
    assert __version__ == (ROOT_DIR / ".VERSION").read_text(encoding="utf-8").strip()


def test_package_version_comes_from_root_version_file() -> None:
    assert __version__ == (ROOT_DIR / ".VERSION").read_text(encoding="utf-8").strip()


def test_create_app_sets_title(prepared_app_settings: AppSettings) -> None:
    app = create_app(prepared_app_settings)

    assert app.title == "Dionysus"
