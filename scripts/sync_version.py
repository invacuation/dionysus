"""Command-line wrapper for repository version synchronization."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dionysus.version_sync import sync_versions


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root. Defaults to the current working directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    changed = sync_versions(args.root)
    if changed:
        print("updated version files:")
        for path in changed:
            print(f"- {path}")
    else:
        print("version files already synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
