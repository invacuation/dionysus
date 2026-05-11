"""Initial administrator bootstrap services."""

import logging

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.config import AppSettings
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models.identity import (
    Group,
    GroupMembership,
    PermissionEffect,
    PrincipalType,
    User,
)

ADMIN_GROUP_DISPLAY_NAME = "Administrators"
ADMIN_GROUP_NAME = "administrators"
ADMIN_PERMISSION = "admin:*"

logger = logging.getLogger(__name__)


class BootstrapAdminError(RuntimeError):
    """Raised when the initial administrator cannot be bootstrapped safely."""


def bootstrap_admin_user(
    session: Session,
    *,
    username: str,
    display_name: str,
    password: str,
) -> User:
    """Create an administrator user for a fresh installation.

    Args:
        session: The database session used for all identity writes.
        username: The username for the administrator account.
        display_name: The human-readable display name for the account.
        password: The raw password to hash through the normal user service.

    Returns:
        The newly created administrator user.

    Raises:
        BootstrapAdminError: If users already exist.
    """

    if _users_exist(session):
        msg = "users already exist; bootstrap admin is only allowed before user creation"
        raise BootstrapAdminError(msg)

    user = _create_admin_user(
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


def bootstrap_admin_from_settings(session: Session, settings: AppSettings) -> User | None:
    """Create the initial administrator from application settings when configured."""

    bootstrap_settings_present = any(
        value is not None
        for value in (
            settings.bootstrap_admin_username,
            settings.bootstrap_admin_password,
            settings.bootstrap_admin_display_name,
        )
    )

    if _users_exist(session):
        if bootstrap_settings_present:
            logger.warning("bootstrap admin environment variables are set but users already exist")
        return None

    if not settings.bootstrap_admin_username or not settings.bootstrap_admin_password:
        msg = "bootstrap admin username and password are required"
        raise BootstrapAdminError(msg)

    display_name = settings.bootstrap_admin_display_name or settings.bootstrap_admin_username
    try:
        with session.begin_nested():
            return bootstrap_admin_user(
                session,
                username=settings.bootstrap_admin_username,
                display_name=display_name,
                password=settings.bootstrap_admin_password,
            )
    except IntegrityError as exc:
        if _users_exist(session):
            logger.warning("bootstrap admin environment variables are set but users already exist")
            return None
        msg = "bootstrap admin could not be created"
        raise BootstrapAdminError(msg) from exc


def _users_exist(session: Session) -> bool:
    """Return whether any user account exists."""

    return (session.scalar(select(func.count()).select_from(User)) or 0) > 0


def _create_admin_user(
    session: Session,
    *,
    username: str,
    display_name: str,
    password: str,
) -> User:
    """Create a user and convert validation errors into sanitized bootstrap errors."""

    try:
        return create_user(
            session,
            username=username,
            display_name=display_name,
            password=password,
        )
    except ValueError as exc:
        raise BootstrapAdminError(_bootstrap_validation_message(exc)) from exc


def _bootstrap_validation_message(exc: ValueError) -> str:
    """Return a sanitized bootstrap validation message."""

    error = str(exc).lower()
    if "username" in error:
        return "bootstrap admin username is invalid"
    if "display name" in error:
        return "bootstrap admin display name is invalid"
    if "password" in error:
        return "bootstrap admin password is invalid"
    return "bootstrap admin settings are invalid"


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
