"""Initial administrator bootstrap services."""

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models.identity import (
    BootstrapLock,
    Group,
    GroupMembership,
    PermissionEffect,
    PrincipalType,
    User,
)

ADMIN_GROUP_DISPLAY_NAME = "Administrators"
ADMIN_GROUP_NAME = "administrators"
ADMIN_PERMISSION = "admin:*"
INITIAL_ADMIN_BOOTSTRAP_LOCK = "initial-admin"


class BootstrapAdminError(RuntimeError):
    """Raised when the initial administrator cannot be bootstrapped safely."""


def bootstrap_admin_user(
    session: Session,
    *,
    username: str,
    display_name: str,
    password: str,
    allow_existing: bool = False,
) -> User:
    """Create an administrator user for a fresh installation.

    Args:
        session: The database session used for all identity writes.
        username: The username for the administrator account.
        display_name: The human-readable display name for the account.
        password: The raw password to hash through the normal user service.
        allow_existing: Whether to allow bootstrapping when users already exist.

    Returns:
        The newly created administrator user.

    Raises:
        BootstrapAdminError: If users already exist and ``allow_existing`` is
            not enabled.
    """

    if not allow_existing:
        _claim_initial_admin_bootstrap(session)
        if _users_exist(session):
            msg = "users already exist; bootstrap admin is only allowed before user creation"
            raise BootstrapAdminError(msg)

    user = create_user(
        session,
        username=username,
        display_name=display_name,
        password=password,
    )
    admin_group = _get_or_create_admin_group(session)
    _ensure_membership(session, admin_group=admin_group, user=user)
    assign_permission(
        session,
        principal_type=PrincipalType.GROUP,
        principal_id=admin_group.id,
        permission=ADMIN_PERMISSION,
        effect=PermissionEffect.ALLOW,
        scope_type=None,
        scope_id=None,
    )
    session.flush()
    return user


def _users_exist(session: Session) -> bool:
    """Return whether any user account exists."""

    return (session.scalar(select(func.count()).select_from(User)) or 0) > 0


def _claim_initial_admin_bootstrap(session: Session) -> BootstrapLock:
    """Claim the one-time initial administrator bootstrap sentinel."""

    lock = BootstrapLock(name=INITIAL_ADMIN_BOOTSTRAP_LOCK)
    try:
        with session.begin_nested():
            session.add(lock)
            session.flush()
    except IntegrityError as exc:
        msg = "bootstrap has already been claimed; initial administrator cannot be created"
        raise BootstrapAdminError(msg) from exc
    return lock


def _get_or_create_admin_group(session: Session) -> Group:
    """Return the protected administrator group, creating it when absent."""

    group = session.scalar(select(Group).where(Group.name == ADMIN_GROUP_NAME))
    if group is None:
        group = Group(
            name=ADMIN_GROUP_NAME,
            display_name=ADMIN_GROUP_DISPLAY_NAME,
            is_protected=True,
        )
        session.add(group)
        session.flush()
        return group

    group.display_name = ADMIN_GROUP_DISPLAY_NAME
    group.is_protected = True
    session.flush()
    return group


def _ensure_membership(session: Session, *, admin_group: Group, user: User) -> GroupMembership:
    """Return the membership linking a user to the administrator group."""

    membership = session.scalar(
        select(GroupMembership).where(
            GroupMembership.group_id == admin_group.id,
            GroupMembership.principal_type == PrincipalType.USER,
            GroupMembership.principal_id == user.id,
        )
    )
    if membership is not None:
        return membership

    membership = GroupMembership(
        group_id=admin_group.id,
        principal_type=PrincipalType.USER,
        principal_id=user.id,
    )
    session.add(membership)
    session.flush()
    return membership
