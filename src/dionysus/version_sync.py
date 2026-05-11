"""Synchronize generated project metadata from the canonical version file."""

from __future__ import annotations

import json
import re
from pathlib import Path

VERSION_FILE = ".dionysus-version"
PYPROJECT_VERSION_RE = re.compile(r'(?m)^version = "([^"]+)"$')
LOCK_PACKAGE_RE = re.compile(r'(?ms)(\[\[package\]\]\nname = "dionysus"\nversion = ")([^"]+)(")')


def read_source_version(root: Path) -> str:
    return (root / VERSION_FILE).read_text(encoding="utf-8").strip()


def replace_once(text: str, pattern: re.Pattern[str], replacement: str, path: str) -> str:
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"Unable to update version in {path}")
    return updated


def sync_pyproject(root: Path, version: str) -> bool:
    path = root / "pyproject.toml"
    original = path.read_text(encoding="utf-8")
    updated = replace_once(original, PYPROJECT_VERSION_RE, f'version = "{version}"', str(path))
    if updated == original:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def sync_frontend_package(root: Path, version: str) -> bool:
    path = root / "frontend" / "package.json"
    package = json.loads(path.read_text(encoding="utf-8"))
    if package["version"] == version:
        return False
    package["version"] = version
    path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    return True


def sync_uv_lock(root: Path, version: str) -> bool:
    path = root / "uv.lock"
    original = path.read_text(encoding="utf-8")
    updated = replace_once(original, LOCK_PACKAGE_RE, rf"\g<1>{version}\g<3>", str(path))
    if updated == original:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def sync_versions(root: Path) -> list[str]:
    version = read_source_version(root)
    changed: list[str] = []
    if sync_pyproject(root, version):
        changed.append("pyproject.toml")
    if sync_frontend_package(root, version):
        changed.append("frontend/package.json")
    if sync_uv_lock(root, version):
        changed.append("uv.lock")
    return changed
