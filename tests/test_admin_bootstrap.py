from pathlib import Path

import pytest
from sqlalchemy import Boolean, Column, DateTime, MetaData, String, Table, select
from sqlalchemy.orm import Session

from dionysus.cli import main
from dionysus.db import create_engine_from_url, create_session_factory
from dionysus.identity.bootstrap import BootstrapAdminError, bootstrap_admin_user
from dionysus.identity.permissions import check_permission
from dionysus.identity.users import authenticate_user, create_user
from dionysus.models import Base
from dionysus.models.identity import (
    BootstrapLock,
    Group,
    GroupMembership,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
    User,
)


def test_cli_bootstrap_admin_help_does_not_offer_raw_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["bootstrap-admin", "--help"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "--password PASSWORD" not in captured.out


def test_cli_bootstrap_admin_rejects_raw_password_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "bootstrap-admin",
                "--username",
                "root",
                "--display-name",
                "Root Admin",
                "--password",
                "correct horse battery staple",
            ]
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "correct horse battery staple" not in captured.err
    assert "correct horse battery staple" not in captured.out


def test_bootstrap_admin_creates_admin_identity(db_session: Session) -> None:
    user = bootstrap_admin_user(
        db_session,
        username="root",
        display_name="Root Admin",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    admin_group = db_session.scalar(select(Group).where(Group.name == "administrators"))
    permission = check_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="admin:*",
        scope_type=None,
        scope_id=None,
    )

    assert user.username == "root"
    assert admin_group is not None
    assert admin_group.id is not None
    assert admin_group.display_name == "Administrators"
    assert admin_group.is_protected
    membership = db_session.scalar(
        select(GroupMembership).where(
            GroupMembership.group_id == admin_group.id,
            GroupMembership.principal_type == PrincipalType.USER,
            GroupMembership.principal_id == user.id,
        )
    )
    assignment = db_session.scalar(
        select(PermissionAssignment).where(
            PermissionAssignment.principal_type == PrincipalType.GROUP,
            PermissionAssignment.principal_id == admin_group.id,
            PermissionAssignment.permission == "admin:*",
            PermissionAssignment.effect == PermissionEffect.ALLOW,
            PermissionAssignment.scope_type.is_(None),
            PermissionAssignment.scope_id.is_(None),
        )
    )
    assert membership is not None
    assert assignment is not None
    assert permission.allowed
    assert authenticate_user(db_session, "root", "correct horse battery staple") is not None


def test_bootstrap_admin_refuses_when_user_already_exists(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice",
        display_name="Alice Example",
        password="password",  # noqa: S106
    )
    db_session.commit()

    with pytest.raises(BootstrapAdminError, match="users already exist"):
        bootstrap_admin_user(
            db_session,
            username="root",
            display_name="Root Admin",
            password="correct horse battery staple",  # noqa: S106
        )


def test_bootstrap_admin_refuses_when_first_run_lock_exists(db_session: Session) -> None:
    db_session.add(BootstrapLock(name="initial-admin"))
    db_session.commit()

    with pytest.raises(BootstrapAdminError, match="bootstrap has already been claimed"):
        bootstrap_admin_user(
            db_session,
            username="root",
            display_name="Root Admin",
            password="correct horse battery staple",  # noqa: S106
        )

    assert db_session.scalar(select(User).where(User.username == "root")) is None


def test_bootstrap_admin_allows_later_admin_when_explicit(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice",
        display_name="Alice Example",
        password="password",  # noqa: S106
    )
    db_session.commit()

    user = bootstrap_admin_user(
        db_session,
        username="root",
        display_name="Root Admin",
        password="correct horse battery staple",  # noqa: S106
        allow_existing=True,
    )
    db_session.commit()

    admin_group = db_session.scalar(select(Group).where(Group.name == "administrators"))

    assert admin_group is not None
    assert admin_group.id is not None
    membership = db_session.scalar(
        select(GroupMembership).where(
            GroupMembership.group_id == admin_group.id,
            GroupMembership.principal_type == PrincipalType.USER,
            GroupMembership.principal_id == user.id,
        )
    )
    assert membership is not None
    assert authenticate_user(db_session, "root", "correct horse battery staple") is not None


def test_cli_bootstrap_admin_creates_user_from_env_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "dionysus.db"
    database_url = f"sqlite:///{database_path}"
    engine = create_engine_from_url(database_url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    monkeypatch.setenv("DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD", "correct horse battery staple")

    exit_code = main(
        [
            "bootstrap-admin",
            "--username",
            "root",
            "--display-name",
            "Root Admin",
        ]
    )

    session_factory = create_session_factory(engine)
    with session_factory() as session:
        user = session.scalar(select(User).where(User.username == "root"))
        admin_group = session.scalar(select(Group).where(Group.name == "administrators"))

        assert exit_code == 0
        assert user is not None
        assert admin_group is not None
        assert authenticate_user(session, "root", "correct horse battery staple") is not None


def test_cli_bootstrap_admin_exits_nonzero_when_users_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "dionysus.db"
    database_url = f"sqlite:///{database_path}"
    engine = create_engine_from_url(database_url)
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        create_user(
            session,
            username="alice",
            display_name="Alice Example",
            password="password",  # noqa: S106
        )
        session.commit()
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    monkeypatch.setenv("DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD", "correct horse battery staple")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "bootstrap-admin",
                "--username",
                "root",
                "--display-name",
                "Root Admin",
            ]
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert "users already exist" in captured.err
    assert "correct horse battery staple" not in captured.err


def test_cli_bootstrap_admin_exits_with_migration_hint_when_bootstrap_locks_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path = tmp_path / "dionysus.db"
    database_url = f"sqlite:///{database_path}"
    engine = create_engine_from_url(database_url)
    old_schema_metadata = MetaData()
    Table(
        "users",
        old_schema_metadata,
        Column("id", String(), primary_key=True),
        Column("username", String(150), nullable=False, unique=True, index=True),
        Column("display_name", String(200), nullable=False),
        Column("is_active", Boolean(), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )
    old_schema_metadata.create_all(engine)
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    monkeypatch.setenv("DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD", "correct horse battery staple")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "bootstrap-admin",
                "--username",
                "root",
                "--display-name",
                "Root Admin",
            ]
        )

    captured = capsys.readouterr()
    combined_output = f"{captured.out}\n{captured.err}"
    assert exc_info.value.code == 1
    assert "alembic upgrade head" in combined_output
    assert "bootstrap_locks" not in combined_output
    assert "INSERT INTO" not in combined_output
    assert "Traceback" not in combined_output
    assert "sqlalchemy.exc" not in combined_output
    assert "correct horse battery staple" not in combined_output
