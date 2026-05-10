import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from dionysus.identity.actors import ActorType, AuthenticatedActor, AuthMethod
from dionysus.identity.authorization import ensure_actor_permission
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models.identity import PermissionEffect, PrincipalType


def _actor_for_user(user_id: str) -> AuthenticatedActor:
    return AuthenticatedActor(
        actor_type=ActorType.USER,
        actor_id=user_id,
        display_name="Alice",
        principal_type=PrincipalType.USER,
        principal_id=user_id,
        auth_method=AuthMethod.SESSION,
        session_id="session-id",
        machine_token_id=None,
        mixed_credentials_present=False,
        bearer_token_present=False,
        session_cookie_present=True,
    )


def test_admin_wildcard_allows_specific_admin_permission(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="admin:*",
        effect=PermissionEffect.ALLOW,
        scope_type=None,
        scope_id=None,
    )
    db_session.commit()

    actor = ensure_actor_permission(
        db_session,
        actor=_actor_for_user(user.id),
        permission="audit_log:view",
        scope_type=None,
        scope_id=None,
    )

    assert actor.principal_id == user.id


def test_specific_scoped_deny_overrides_admin_wildcard(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="admin:*",
        effect=PermissionEffect.ALLOW,
        scope_type=None,
        scope_id=None,
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="audit_log:view",
        effect=PermissionEffect.DENY,
        scope_type="project",
        scope_id="project-1",
    )
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        ensure_actor_permission(
            db_session,
            actor=_actor_for_user(user.id),
            permission="audit_log:view",
            scope_type="project",
            scope_id="project-1",
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Forbidden"


def test_missing_permission_grant_is_forbidden(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        ensure_actor_permission(
            db_session,
            actor=_actor_for_user(user.id),
            permission="audit_log:view",
            scope_type=None,
            scope_id=None,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Forbidden"
