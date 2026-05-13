import json
import tomllib
from pathlib import Path

ROOT_DIR = Path(__file__).parents[1]
CI_WORKFLOW = ROOT_DIR / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
RELEASE_PLEASE_CONFIG = ROOT_DIR / "release-please-config.json"
PYPROJECT = ROOT_DIR / "pyproject.toml"
UV_LOCK = ROOT_DIR / "uv.lock"


def test_release_image_publish_builds_multi_arch_manifest() -> None:
    workflow = RELEASE_WORKFLOW.read_text()

    assert "docker/setup-qemu-action" in workflow
    assert "platforms: linux/amd64,linux/arm64" in workflow


def test_lockfile_check_runs_before_dependency_sync() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert workflow.index("run: uv lock --check") < workflow.index("run: uv sync --dev")


def test_uv_lock_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads(PYPROJECT.read_text())
    uv_lock = tomllib.loads(UV_LOCK.read_text())

    project_version = pyproject["project"]["version"]
    locked_package = next(
        package for package in uv_lock["package"] if package["name"] == "dionysus"
    )

    assert locked_package["version"] == project_version


def test_release_please_updates_uv_lock_package_version() -> None:
    config = json.loads(RELEASE_PLEASE_CONFIG.read_text())

    uv_lock_extra_file = next(
        extra_file
        for extra_file in config["packages"]["."]["extra-files"]
        if extra_file["path"] == "uv.lock"
    )

    assert uv_lock_extra_file == {
        "type": "toml",
        "path": "uv.lock",
        "jsonpath": '$.package[?(@.name.value=="dionysus")].version',
    }
