"""Command-line wrapper for the repository version bump check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dionysus.version_check import VersionCheckError, validate_versions


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr-title", required=True, help="Pull request title to validate.")
    parser.add_argument(
        "--base-version",
        help="Optional base version override. Defaults to max(origin/main:.VERSION, v* tags).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root. Defaults to the current working directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        validate_versions(args.root, args.pr_title, args.base_version)
    except VersionCheckError as exc:
        print(f"version check failed: {exc}", file=sys.stderr)
        return 1
    print("version check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
