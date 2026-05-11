import json
from pathlib import Path

from dionysus.version_sync import sync_versions


def write_project_files(root: Path) -> None:
    (root / ".dionysus-version").write_text("0.5.2\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "dionysus"',
                'version = "0.1.0"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    frontend = root / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        json.dumps({"name": "example-frontend", "version": "0.1.0"}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "dionysus"',
                'version = "0.1.0"',
                'source = { editable = "." }',
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_sync_versions_updates_generated_version_files(tmp_path: Path) -> None:
    write_project_files(tmp_path)

    changed = sync_versions(tmp_path)

    assert changed == ["pyproject.toml", "frontend/package.json", "uv.lock"]
    assert 'version = "0.5.2"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        json.loads((tmp_path / "frontend" / "package.json").read_text(encoding="utf-8"))["version"]
        == "0.5.2"
    )
    assert 'version = "0.5.2"' in (tmp_path / "uv.lock").read_text(encoding="utf-8")


def test_sync_versions_reports_no_changes_when_files_are_current(tmp_path: Path) -> None:
    write_project_files(tmp_path)
    sync_versions(tmp_path)

    assert sync_versions(tmp_path) == []
