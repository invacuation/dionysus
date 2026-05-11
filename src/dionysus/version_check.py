"""Validate repository version bump policy."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
TITLE_RE = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(\([a-z0-9._/-]+\))?"
    r"(?P<breaking>!)?: .+"
)


@dataclass(frozen=True)
class VersionCheckResult:
    """Version check context for human-readable CI output."""

    passed: bool
    pr_title: str
    base_version: str
    bump_level: str
    expected_version: str
    versions: dict[str, str]


class VersionCheckError(Exception):
    """Raised when the repository version policy is not satisfied."""

    def __init__(self, message_or_result: str | VersionCheckResult) -> None:
        self.result = (
            message_or_result if isinstance(message_or_result, VersionCheckResult) else None
        )
        message = (
            format_failure_message(message_or_result)
            if isinstance(message_or_result, VersionCheckResult)
            else message_or_result
        )
        super().__init__(message)


def parse_version(version: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(version)
    if match is None:
        raise VersionCheckError(f"Invalid semantic version: {version!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def bump_version(version: str, level: str) -> str:
    major, minor, patch = parse_version(version)
    if level == "none":
        return version
    if level == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    if level == "major":
        return f"{major + 1}.0.0"
    raise VersionCheckError(f"Unknown bump level: {level}")


def bump_level_for_title(title: str) -> str:
    match = TITLE_RE.fullmatch(title)
    if match is None:
        raise VersionCheckError(
            "PR title must be a conventional commit, for example 'fix: handle stale findings'."
        )

    commit_type = match.group("type")
    if match.group("breaking") or commit_type == "feat":
        return "minor"
    if commit_type in {"docs", "chore"}:
        return "none"
    return "patch"


def expected_version_for_title(title: str, base_version: str) -> str:
    return bump_version(base_version, bump_level_for_title(title))


def describe_bump_level(level: str) -> str:
    if level == "none":
        return "no"
    return level


def max_version(versions: list[str]) -> str:
    if not versions:
        raise VersionCheckError("No base versions were found.")
    return max(versions, key=parse_version)


def read_project_versions(root: Path) -> dict[str, str]:
    version_file = root / ".VERSION"
    pyproject_file = root / "pyproject.toml"
    package_file = root / "frontend" / "package.json"

    pyproject = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
    package = json.loads(package_file.read_text(encoding="utf-8"))

    return {
        ".VERSION": version_file.read_text(encoding="utf-8").strip(),
        "pyproject.toml": pyproject["project"]["version"],
        "frontend/package.json": package["version"],
    }


def git_output(args: list[str], root: Path) -> str:
    git = shutil.which("git")
    if git is None:
        raise VersionCheckError("Unable to find git on PATH.")

    result = subprocess.run(  # noqa: S603
        [git, *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def discover_base_version(root: Path) -> str:
    versions: list[str] = []

    try:
        versions.append(git_output(["show", "origin/main:.VERSION"], root))
    except subprocess.CalledProcessError as exc:
        raise VersionCheckError(f"Unable to read origin/main:.VERSION: {exc.stderr}") from exc

    tags = git_output(["tag", "--list", "v*"], root).splitlines()
    versions.extend(
        tag.removeprefix("v") for tag in tags if VERSION_RE.fullmatch(tag.removeprefix("v"))
    )

    return max_version(versions)


def validate_versions(
    root: Path, pr_title: str, base_version: str | None = None
) -> VersionCheckResult:
    base = base_version if base_version is not None else discover_base_version(root)
    bump_level = bump_level_for_title(pr_title)
    expected = bump_version(base, bump_level)
    versions = read_project_versions(root)

    result = VersionCheckResult(
        passed=all(version == expected for version in versions.values()),
        pr_title=pr_title,
        base_version=base,
        bump_level=bump_level,
        expected_version=expected,
        versions=versions,
    )
    if not result.passed:
        raise VersionCheckError(result)
    return result


def format_version_line(path: str, actual: str, expected: str) -> str:
    if actual == expected:
        return f"- {path} has been bumped to {expected}."
    return f"- {path} is {actual}; change it to {expected}."


def format_result_message(result: VersionCheckResult) -> str:
    status = "passed" if result.passed else "failed"
    lines = [
        f"version check {status}:",
        f"- PR title {result.pr_title!r} requires a "
        f"{describe_bump_level(result.bump_level)} version bump.",
        f"- Base version is {result.base_version}; expected version is {result.expected_version}.",
    ]
    lines.extend(
        format_version_line(path, result.versions[path], result.expected_version)
        for path in [".VERSION", "pyproject.toml", "frontend/package.json"]
    )
    return "\n".join(lines)


def format_success_message(result: VersionCheckResult) -> str:
    return format_result_message(result)


def format_failure_message(error_or_result: VersionCheckError | VersionCheckResult) -> str:
    if isinstance(error_or_result, VersionCheckError):
        if error_or_result.result is None:
            return f"version check failed: {error_or_result}"
        result = error_or_result.result
    else:
        result = error_or_result
    return format_result_message(result)
