from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

from dionysus import __version__
from dionysus import version as dionysus_version
from dionysus.app import create_app
from dionysus.config import AppSettings

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_package_version() -> None:
    assert __version__ == package_version("dionysus")


def test_package_version_does_not_require_root_version_file() -> None:
    assert not (ROOT_DIR / ".dionysus-version").exists()


def test_package_version_can_fall_back_to_pyproject(
    tmp_path: Path,
    monkeypatch,
) -> None:
    package_dir = tmp_path / "src" / "dionysus"
    package_dir.mkdir(parents=True)
    module_file = package_dir / "version.py"
    module_file.write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "dionysus"\nversion = "9.8.7"\n',
        encoding="utf-8",
    )

    def raise_package_not_found(_distribution_name: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(dionysus_version, "__file__", str(module_file))
    monkeypatch.setattr(dionysus_version, "metadata_version", raise_package_not_found)

    assert dionysus_version.read_app_version() == "9.8.7"


def test_create_app_sets_title(prepared_app_settings: AppSettings) -> None:
    app = create_app(prepared_app_settings)

    assert app.title == "Dionysus"
