"""Application version helpers."""

import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version
from pathlib import Path


def read_app_version() -> str:
    """Read the application version from package metadata.

    Returns:
        Version string from installed package metadata or local project metadata.

    Raises:
        RuntimeError: If the version cannot be found near the installed package.
    """

    try:
        return metadata_version("dionysus")
    except PackageNotFoundError:
        pass

    for parent in Path(__file__).resolve().parents:
        pyproject_file = parent / "pyproject.toml"
        if pyproject_file.is_file():
            pyproject = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
            version = pyproject.get("project", {}).get("version")
            if isinstance(version, str):
                return version

    raise RuntimeError("Unable to locate dionysus package version")
