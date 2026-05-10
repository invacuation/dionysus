"""Application version helpers."""

from pathlib import Path


def read_app_version() -> str:
    """Read the application version from the repository version file.

    Returns:
        Version string stored in the repository-root `.VERSION` file.

    Raises:
        RuntimeError: If the version file cannot be found near the installed package.
    """

    for parent in Path(__file__).resolve().parents:
        version_file = parent / ".VERSION"
        if version_file.is_file():
            return version_file.read_text(encoding="utf-8").strip()
    raise RuntimeError("Unable to locate .VERSION file")
