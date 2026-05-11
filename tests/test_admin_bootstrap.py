import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.config import AppSettings
from dionysus.identity import bootstrap as bootstrap_service
from dionysus.identity.bootstrap import (
    BootstrapAdminError,
    bootstrap_admin_from_settings,
    bootstrap_admin_user,
)
from dionysus.identity.permissions import check_permission
from dionysus.identity.users import authenticate_user, create_user
from dionysus.models.identity import (
    Group,
    GroupMembership,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
    User,
)


def test_bootstrap_admin_creates_admin_identity(db_session: Session) -> None:
    user = bootstrap_admin_user(
        db_session,
        username="admin@example.com",
        display_name="Root Admin",
        password="change-me-now-please",  # noqa: S106
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

    assert user.username == "admin@example.com"
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
    assert authenticate_user(db_session, "admin@example.com", "change-me-now-please") is not None


def test_bootstrap_admin_from_settings_defaults_display_name_to_username(
    db_session: Session,
) -> None:
    user = bootstrap_admin_from_settings(
        db_session,
        AppSettings(
            bootstrap_admin_username="admin@example.com",
            bootstrap_admin_password="change-me-now-please",  # noqa: S106
        ),
    )
    db_session.commit()

    assert user is not None
    assert user.username == "admin@example.com"
    assert user.display_name == "admin@example.com"
    assert authenticate_user(db_session, "admin@example.com", "change-me-now-please") is not None


@pytest.mark.parametrize(
    ("username", "password"),
    [
        (None, None),
        ("admin@example.com", None),
        (None, "change-me-now-please"),
        ("", "change-me-now-please"),
        ("admin@example.com", ""),
    ],
)
def test_bootstrap_admin_from_settings_requires_username_and_password(
    db_session: Session,
    username: str | None,
    password: str | None,
) -> None:
    with pytest.raises(BootstrapAdminError) as exc_info:
        bootstrap_admin_from_settings(
            db_session,
            AppSettings(
                bootstrap_admin_username=username,
                bootstrap_admin_password=password,
            ),
        )

    message = str(exc_info.value)
    assert "username and password are required" in message
    assert "change-me-now-please" not in message


def test_bootstrap_admin_from_settings_rejects_invalid_password(
    db_session: Session,
) -> None:
    with pytest.raises(BootstrapAdminError) as exc_info:
        bootstrap_admin_from_settings(
            db_session,
            AppSettings(
                bootstrap_admin_username="admin@example.com",
                bootstrap_admin_password="short",  # noqa: S106
            ),
        )

    message = str(exc_info.value)
    assert "password" in message
    assert "short" not in message
    assert db_session.scalar(select(User).where(User.username == "admin@example.com")) is None


def test_bootstrap_admin_from_settings_warns_and_skips_when_users_exist(
    db_session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="change-me-now-please",  # noqa: S106
    )
    db_session.commit()

    with caplog.at_level("WARNING"):
        user = bootstrap_admin_from_settings(
            db_session,
            AppSettings(
                bootstrap_admin_username="admin@example.com",
                bootstrap_admin_password="change-me-now-please",  # noqa: S106
            ),
        )

    assert user is None
    assert "bootstrap admin environment variables are set but users already exist" in caplog.text
    assert db_session.scalar(select(User).where(User.username == "admin@example.com")) is None


def test_bootstrap_admin_from_settings_warns_and_skips_when_racing_user_creation(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="change-me-now-please",  # noqa: S106
    )
    db_session.commit()

    original_users_exist = bootstrap_service._users_exist
    users_exist_calls = 0

    def users_exist_after_initial_race_check(session: Session) -> bool:
        nonlocal users_exist_calls
        users_exist_calls += 1
        if users_exist_calls == 1:
            return False
        return original_users_exist(session)

    def raise_integrity_error(*args: object, **kwargs: object) -> None:
        raise IntegrityError("insert user", {}, Exception("duplicate key"))

    monkeypatch.setattr(
        bootstrap_service,
        "_users_exist",
        users_exist_after_initial_race_check,
    )
    monkeypatch.setattr(
        bootstrap_service,
        "bootstrap_admin_user",
        raise_integrity_error,
    )

    with caplog.at_level("WARNING"):
        user = bootstrap_admin_from_settings(
            db_session,
            AppSettings(
                bootstrap_admin_username="admin@example.com",
                bootstrap_admin_password="change-me-now-please",  # noqa: S106
            ),
        )

    assert user is None
    assert users_exist_calls == 2
    assert "bootstrap admin environment variables are set but users already exist" in caplog.text
    assert db_session.scalar(select(User).where(User.username == "alice@example.com")) is not None
    assert db_session.scalar(select(User).where(User.username == "admin@example.com")) is None


def test_bootstrap_admin_from_settings_warns_when_user_appears_before_inner_check(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="change-me-now-please",  # noqa: S106
    )
    db_session.commit()

    original_users_exist = bootstrap_service._users_exist
    users_exist_calls = 0

    def users_exist_after_initial_race_check(session: Session) -> bool:
        nonlocal users_exist_calls
        users_exist_calls += 1
        if users_exist_calls == 1:
            return False
        return original_users_exist(session)

    def raise_users_exist_error(*args: object, **kwargs: object) -> None:
        msg = "users already exist; bootstrap admin is only allowed before user creation"
        raise BootstrapAdminError(msg)

    monkeypatch.setattr(
        bootstrap_service,
        "_users_exist",
        users_exist_after_initial_race_check,
    )
    monkeypatch.setattr(
        bootstrap_service,
        "bootstrap_admin_user",
        raise_users_exist_error,
    )

    with caplog.at_level("WARNING"):
        user = bootstrap_admin_from_settings(
            db_session,
            AppSettings(
                bootstrap_admin_username="admin@example.com",
                bootstrap_admin_password="change-me-now-please",  # noqa: S106
            ),
        )

    assert user is None
    assert users_exist_calls == 2
    assert "bootstrap admin environment variables are set but users already exist" in caplog.text
    assert db_session.scalar(select(User).where(User.username == "alice@example.com")) is not None
    assert db_session.scalar(select(User).where(User.username == "admin@example.com")) is None


def test_bootstrap_admin_from_settings_skips_silently_when_users_exist_without_settings(
    db_session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="change-me-now-please",  # noqa: S106
    )
    db_session.commit()

    with caplog.at_level("WARNING"):
        user = bootstrap_admin_from_settings(db_session, AppSettings())

    assert user is None
    assert (
        "bootstrap admin environment variables are set but users already exist" not in caplog.text
    )


def test_bootstrap_admin_refuses_when_user_already_exists(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="change-me-now-please",  # noqa: S106
    )
    db_session.commit()

    with pytest.raises(BootstrapAdminError, match="users already exist"):
        bootstrap_admin_user(
            db_session,
            username="admin@example.com",
            display_name="Root Admin",
            password="change-me-now-please",  # noqa: S106
        )
