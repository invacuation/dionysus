"""Command-line administration entry points."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence

from sqlalchemy.exc import OperationalError

from dionysus.config import AppSettings
from dionysus.db import create_engine_from_url, create_session_factory
from dionysus.identity.bootstrap import BootstrapAdminError, bootstrap_admin_user

BOOTSTRAP_PASSWORD_ENV = "DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD"  # noqa: S105
BOOTSTRAP_SCHEMA_NOT_READY_MESSAGE = (
    "bootstrap-admin failed: database schema is not up to date; "
    "run `uv --cache-dir .uv-cache run alembic upgrade head` and retry"
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Dionysus administration CLI.

    Args:
        argv: Optional command-line arguments excluding the executable name.

    Returns:
        The process exit code.

    Raises:
        SystemExit: If an administrative command fails in an expected,
            sanitized way.
    """

    parser = _build_parser()
    if _has_raw_password_argument(argv if argv is not None else sys.argv[1:]):
        parser.error(
            "--password is not supported; use DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD, "
            "--password-stdin, or the interactive prompt"
        )
    args = parser.parse_args(argv)

    if args.command == "bootstrap-admin":
        return _bootstrap_admin(args)

    parser.print_help()
    return 1


def _has_raw_password_argument(argv: Sequence[str]) -> bool:
    """Return whether command arguments include the unsafe raw password flag."""

    return any(arg == "--password" or arg.startswith("--password=") for arg in argv)


def _build_parser() -> argparse.ArgumentParser:
    """Return the root administration argument parser."""

    parser = argparse.ArgumentParser(prog="dionysus-admin")
    subparsers = parser.add_subparsers(dest="command")

    bootstrap = subparsers.add_parser(
        "bootstrap-admin",
        help="create the initial administrator user",
    )
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--display-name", required=True)
    bootstrap.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the administrator password from standard input",
    )
    bootstrap.add_argument(
        "--allow-existing",
        action="store_true",
        help="allow adding an administrator when users already exist",
    )
    return parser


def _bootstrap_admin(args: argparse.Namespace) -> int:
    """Create an administrator user from parsed CLI arguments.

    Args:
        args: Parsed arguments for the ``bootstrap-admin`` command.

    Returns:
        A zero exit code after the transaction commits.

    Raises:
        SystemExit: If bootstrap preconditions fail or no password is supplied.
    """

    password = os.environ.get(BOOTSTRAP_PASSWORD_ENV)
    if password is None and args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    if password is None:
        password = getpass.getpass("Admin password: ")
    if not password:
        print("bootstrap-admin failed: password is required", file=sys.stderr)
        raise SystemExit(1)

    settings = AppSettings()
    engine = create_engine_from_url(settings.database_url)
    session_factory = create_session_factory(engine)

    with session_factory() as session:
        try:
            user = bootstrap_admin_user(
                session,
                username=args.username,
                display_name=args.display_name,
                password=password,
                allow_existing=args.allow_existing,
            )
            session.commit()
        except BootstrapAdminError as exc:
            session.rollback()
            print(f"bootstrap-admin failed: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        except OperationalError as exc:
            session.rollback()
            if _is_bootstrap_schema_not_ready(exc):
                print(BOOTSTRAP_SCHEMA_NOT_READY_MESSAGE, file=sys.stderr)
                raise SystemExit(1) from exc
            raise

    print(f"Created administrator user {user.username!r}.")
    return 0


def _is_bootstrap_schema_not_ready(exc: OperationalError) -> bool:
    """Return whether an operational error came from the pre-lock schema."""

    original_error = str(exc.orig).lower()
    return "bootstrap_locks" in original_error and (
        "no such table" in original_error
        or "undefined table" in original_error
        or "does not exist" in original_error
    )


if __name__ == "__main__":
    raise SystemExit(main())
