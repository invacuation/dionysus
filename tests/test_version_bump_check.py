from pathlib import Path
from re import escape

import pytest

from dionysus.version_check import (
    VersionCheckError,
    bump_version,
    expected_version_for_title,
    max_version,
    read_project_versions,
    validate_versions,
)


def write_project_versions(root: Path, version: str) -> None:
    (root / ".VERSION").write_text(f"{version}\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "example"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    frontend = root / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        f'{{"name": "example-frontend", "version": "{version}"}}\n',
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("version", "level", "expected"),
    [
        ("0.3.0", "none", "0.3.0"),
        ("0.3.0", "patch", "0.3.1"),
        ("0.3.0", "minor", "0.4.0"),
        ("0.3.0", "major", "1.0.0"),
    ],
)
def test_bump_version(version: str, level: str, expected: str) -> None:
    assert bump_version(version, level) == expected


@pytest.mark.parametrize(
    ("title", "base_version", "expected"),
    [
        ("docs: update README", "0.3.0", "0.3.0"),
        ("chore: update tooling", "0.3.0", "0.3.0"),
        ("fix: handle stale findings", "0.3.0", "0.3.1"),
        ("ci: enforce version bumps", "0.3.0", "0.3.1"),
        ("feat(imports): add scanner metadata", "0.3.0", "0.4.0"),
        ("feat!: replace permission model", "0.3.0", "0.4.0"),
    ],
)
def test_expected_version_for_title(title: str, base_version: str, expected: str) -> None:
    assert expected_version_for_title(title, base_version) == expected


def test_expected_version_rejects_non_conventional_title() -> None:
    with pytest.raises(VersionCheckError, match="conventional"):
        expected_version_for_title("Update the thing", "0.3.0")


def test_max_version_uses_latest_semver_value() -> None:
    assert max_version(["0.3.0", "0.10.0", "0.4.0"]) == "0.10.0"


def test_read_project_versions_reads_all_canonical_files(tmp_path: Path) -> None:
    write_project_versions(tmp_path, "0.3.1")

    assert read_project_versions(tmp_path) == {
        ".VERSION": "0.3.1",
        "pyproject.toml": "0.3.1",
        "frontend/package.json": "0.3.1",
    }


def test_validate_versions_accepts_expected_version(tmp_path: Path) -> None:
    write_project_versions(tmp_path, "0.3.1")

    validate_versions(tmp_path, "fix: handle stale findings", base_version="0.3.0")


def test_validate_versions_rejects_missing_bump(tmp_path: Path) -> None:
    write_project_versions(tmp_path, "0.3.0")

    with pytest.raises(VersionCheckError, match=escape("Expected version 0.3.1")):
        validate_versions(tmp_path, "fix: handle stale findings", base_version="0.3.0")


def test_validate_versions_rejects_mismatched_project_versions(tmp_path: Path) -> None:
    write_project_versions(tmp_path, "0.3.1")
    (tmp_path / "frontend" / "package.json").write_text(
        '{"name": "example-frontend", "version": "0.3.0"}\n',
        encoding="utf-8",
    )

    with pytest.raises(VersionCheckError, match=escape("frontend/package.json")):
        validate_versions(tmp_path, "fix: handle stale findings", base_version="0.3.0")
