import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.identity.permissions import (
    PermissionCheck,
    assign_permission,
    check_permission,
)
from dionysus.identity.users import create_user
from dionysus.models.identity import (
    Group,
    GroupMembership,
    MachineCredential,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
)


def test_direct_grant_allows_permission(db_session: Session) -> None:
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
        permission="project:view",
        effect=PermissionEffect.ALLOW,
        scope_type="project",
        scope_id="project-1",
    )
    db_session.commit()

    result = check_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        scope_type="project",
        scope_id="project-1",
    )

    assert result.allowed
    assert "direct allow" in result.explanation


def test_explicit_deny_overrides_group_grant(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )
    group = Group(name="developers", display_name="Developers")
    db_session.add(group)
    db_session.flush()
    db_session.add(
        GroupMembership(
            group_id=group.id,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
        )
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.GROUP,
        principal_id=group.id,
        permission="project:view",
        effect=PermissionEffect.ALLOW,
        scope_type="project",
        scope_id="dolor",
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        effect=PermissionEffect.DENY,
        scope_type="project",
        scope_id="dolor",
    )
    db_session.commit()

    result = check_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        scope_type="project",
        scope_id="dolor",
    )

    assert not result.allowed
    assert "explicit deny" in result.explanation
    assert "developers" in result.explanation


def test_no_grant_denies_permission(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )
    db_session.commit()

    result: PermissionCheck = check_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        scope_type="project",
        scope_id="project-1",
    )

    assert not result.allowed
    assert "no matching grant" in result.explanation


def test_half_scoped_assignment_raises_value_error(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )

    with pytest.raises(
        ValueError,
        match="scope_type and scope_id must both be set or both be None",
    ):
        assign_permission(
            db_session,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            permission="project:view",
            effect=PermissionEffect.ALLOW,
            scope_type="project",
            scope_id=None,
        )


def test_half_scoped_check_raises_value_error(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )

    with pytest.raises(
        ValueError,
        match="scope_type and scope_id must both be set or both be None",
    ):
        check_permission(
            db_session,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            permission="project:view",
            scope_type=None,
            scope_id="project-1",
        )


def test_duplicate_exact_assignment_returns_existing_row(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice",
        password="password",  # noqa: S106
    )

    first = assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        effect=PermissionEffect.ALLOW,
        scope_type="project",
        scope_id="project-1",
    )
    second = assign_permission(
        db_session,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        permission="project:view",
        effect=PermissionEffect.ALLOW,
        scope_type="project",
        scope_id="project-1",
    )

    assignments = list(db_session.scalars(select(PermissionAssignment)))

    assert second is first
    assert len(assignments) == 1


def test_machine_credential_can_receive_group_permissions(db_session: Session) -> None:
    machine = MachineCredential(
        name="trivy-uploader",
        client_secret_digest="digest",  # noqa: S106
    )
    group = Group(name="scan-uploaders", display_name="Scan Uploaders")
    db_session.add_all([machine, group])
    db_session.flush()
    db_session.add(
        GroupMembership(
            group_id=group.id,
            principal_type=PrincipalType.MACHINE,
            principal_id=machine.id,
        )
    )
    assign_permission(
        db_session,
        principal_type=PrincipalType.GROUP,
        principal_id=group.id,
        permission="scan:upload",
        effect=PermissionEffect.ALLOW,
        scope_type="project",
        scope_id="project-1",
    )
    db_session.commit()

    result = check_permission(
        db_session,
        principal_type=PrincipalType.MACHINE,
        principal_id=machine.id,
        permission="scan:upload",
        scope_type="project",
        scope_id="project-1",
    )

    assert result.allowed
    assert "group allow" in result.explanation
