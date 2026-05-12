"""JSON API routes for admin access management."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.identity.permissions import KNOWN_PERMISSIONS, assign_permission
from dionysus.identity.users import set_user_password
from dionysus.models.identity import (
    Group,
    GroupMembership,
    MachineCredential,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
    User,
)

router = APIRouter(prefix="/api/admin/access", tags=["access-management"])
access_manage_actor_dependency = Depends(require_permission("access:manage"))
PROTECTED_GROUPS = {
    "administrators": "Administrators",
    "users": "Users",
    "security-reviewers": "Security Reviewers",
}
PROTECTED_GROUP_PERMISSIONS = {
    "users": (
        "finding:comment",
        "finding:status_change:request",
        "finding:view",
        "project:view",
        "report:view",
    ),
    "security-reviewers": (
        "finding:comment",
        "finding:status_change:approve",
        "finding:status_change:request",
        "finding:view",
        "import:history:view",
        "project:view",
        "report:view",
    ),
}


class UserAccessResponse(BaseModel):
    """Safe response body for a user account."""

    model_config = ConfigDict(extra="forbid")

    id: str
    username: str
    display_name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class MachineCredentialAccessResponse(BaseModel):
    """Safe response body for a machine credential."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    client_id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None


class GroupResponse(BaseModel):
    """Response body for an access-management group."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    display_name: str
    is_protected: bool
    created_at: datetime
    updated_at: datetime


class MembershipResponse(BaseModel):
    """Response body for a group membership."""

    model_config = ConfigDict(extra="forbid")

    id: str
    group_id: str
    principal_type: PrincipalType
    principal_id: str
    created_at: datetime
    updated_at: datetime


class PermissionAssignmentResponse(BaseModel):
    """Response body for a permission assignment."""

    model_config = ConfigDict(extra="forbid")

    id: str
    principal_type: PrincipalType
    principal_id: str
    permission: str
    effect: PermissionEffect
    scope_type: str | None
    scope_id: str | None
    created_at: datetime
    updated_at: datetime


class AccessListResponse(BaseModel):
    """Response body for the access-management overview."""

    model_config = ConfigDict(extra="forbid")

    users: list[UserAccessResponse]
    machine_credentials: list[MachineCredentialAccessResponse]
    groups: list[GroupResponse]
    memberships: list[MembershipResponse]
    permission_assignments: list[PermissionAssignmentResponse]
    available_permissions: list[str]


class GroupCreateRequest(BaseModel):
    """Request body for creating a custom group."""

    model_config = ConfigDict(extra="forbid")

    name: str
    display_name: str


class MembershipCreateRequest(BaseModel):
    """Request body for adding a principal to a group."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    principal_type: PrincipalType
    principal_id: str


class PermissionAssignRequest(BaseModel):
    """Request body for assigning an allow or deny permission."""

    model_config = ConfigDict(extra="forbid")

    principal_type: PrincipalType
    principal_id: str
    permission: str
    effect: PermissionEffect
    scope_type: str | None = None
    scope_id: str | None = None


class UserPasswordSetRequest(BaseModel):
    """Request body for replacing a user's local password credential."""

    model_config = ConfigDict(extra="forbid")

    new_password: str


@router.get("", response_model=AccessListResponse)
def access_list_api(
    request: Request,
    _actor: AuthenticatedActor = access_manage_actor_dependency,
) -> AccessListResponse:
    """Return safe access-management identity and permission data.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.

    Returns:
        JSON-serializable users, credentials, groups, memberships, and permissions.

    Raises:
        HTTPException: If authentication fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        _ensure_protected_groups(session)
        users = session.scalars(select(User).order_by(User.username)).all()
        credentials = session.scalars(
            select(MachineCredential).order_by(MachineCredential.created_at)
        ).all()
        groups = session.scalars(select(Group).order_by(Group.name)).all()
        memberships = session.scalars(
            select(GroupMembership).order_by(GroupMembership.created_at)
        ).all()
        assignments = session.scalars(
            select(PermissionAssignment).order_by(PermissionAssignment.created_at)
        ).all()
        session.commit()
        return AccessListResponse(
            users=[_user_response(user) for user in users],
            machine_credentials=[
                _machine_credential_response(credential) for credential in credentials
            ],
            groups=[_group_response(group) for group in groups],
            memberships=[_membership_response(membership) for membership in memberships],
            permission_assignments=[
                _permission_assignment_response(assignment) for assignment in assignments
            ],
            available_permissions=list(KNOWN_PERMISSIONS),
        )


def _ensure_protected_groups(session: Session) -> None:
    existing = {
        group.name: group
        for group in session.scalars(select(Group).where(Group.name.in_(PROTECTED_GROUPS))).all()
    }
    for name, display_name in PROTECTED_GROUPS.items():
        group = existing.get(name)
        if group is None:
            group = _get_or_create_protected_group(
                session,
                name=name,
                display_name=display_name,
            )
        else:
            group.display_name = display_name
            group.is_protected = True
        for permission in PROTECTED_GROUP_PERMISSIONS.get(name, ()):
            assign_permission(
                session,
                principal_type=PrincipalType.GROUP,
                principal_id=group.id,
                permission=permission,
                effect=PermissionEffect.ALLOW,
                scope_type=None,
                scope_id=None,
            )
    session.flush()


def _get_or_create_protected_group(
    session: Session,
    *,
    name: str,
    display_name: str,
) -> Group:
    group = _protected_group_by_name(session, name)
    if group is not None:
        group.display_name = display_name
        group.is_protected = True
        return group

    try:
        with session.begin_nested():
            return _create_protected_group(session, name=name, display_name=display_name)
    except IntegrityError:
        group = _protected_group_by_name(session, name)
        if group is None:
            raise
        group.display_name = display_name
        group.is_protected = True
        return group


def _protected_group_by_name(session: Session, name: str) -> Group | None:
    return session.scalar(select(Group).where(Group.name == name))


def _create_protected_group(session: Session, *, name: str, display_name: str) -> Group:
    group = Group(name=name, display_name=display_name, is_protected=True)
    session.add(group)
    session.flush()
    return group


@router.post(
    "/groups",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
)
def group_create_api(
    request: Request,
    payload: GroupCreateRequest,
    actor: AuthenticatedActor = access_manage_actor_dependency,
) -> GroupResponse:
    """Create a custom group for access management.

    Args:
        request: Incoming request containing application state.
        payload: Custom group name and display name.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The created custom group.

    Raises:
        HTTPException: If authentication fails or the group name already exists.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        existing = session.scalar(select(Group).where(Group.name == payload.name))
        if existing is not None:
            raise _duplicate_group_conflict()
        group = Group(
            name=payload.name,
            display_name=payload.display_name,
            is_protected=False,
        )
        session.add(group)
        session.flush()
        record_audit_event(
            session,
            event_type="access.group.create",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="group",
            target_id=group.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "name": group.name,
                "display_name": group.display_name,
                "is_protected": group.is_protected,
            },
        )
        session.commit()
        return _group_response(group)


@router.post(
    "/memberships",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
def membership_create_api(
    request: Request,
    payload: MembershipCreateRequest,
    actor: AuthenticatedActor = access_manage_actor_dependency,
) -> MembershipResponse:
    """Add a user, machine, or group principal to a group.

    Args:
        request: Incoming request containing application state.
        payload: Target group and principal reference to add.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The existing or newly created membership.

    Raises:
        HTTPException: If authentication fails, the target group is unknown, the principal is
            unknown, or membership persistence fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        _get_group_or_404(session, payload.group_id)
        _ensure_principal_exists(session, payload.principal_type, payload.principal_id)
        membership = session.scalar(
            select(GroupMembership).where(
                GroupMembership.group_id == payload.group_id,
                GroupMembership.principal_type == payload.principal_type,
                GroupMembership.principal_id == payload.principal_id,
            )
        )
        if membership is None:
            membership = GroupMembership(
                group_id=payload.group_id,
                principal_type=payload.principal_type,
                principal_id=payload.principal_id,
            )
            session.add(membership)
            session.flush()
        record_audit_event(
            session,
            event_type="access.membership.add",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="group_membership",
            target_id=membership.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "group_id": membership.group_id,
                "principal_type": membership.principal_type,
                "principal_id": membership.principal_id,
            },
        )
        session.commit()
        return _membership_response(membership)


@router.post(
    "/permissions",
    response_model=PermissionAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def permission_assign_api(
    request: Request,
    payload: PermissionAssignRequest,
    actor: AuthenticatedActor = access_manage_actor_dependency,
) -> PermissionAssignmentResponse:
    """Assign an allow or deny permission to a principal.

    Args:
        request: Incoming request containing application state.
        payload: Principal, effect, permission, and optional exact scope.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The existing or newly created permission assignment.

    Raises:
        HTTPException: If authentication fails, the principal is unknown, or scope fields are
            internally inconsistent.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        _ensure_principal_exists(session, payload.principal_type, payload.principal_id)
        try:
            assignment = assign_permission(
                session,
                principal_type=payload.principal_type,
                principal_id=payload.principal_id,
                permission=payload.permission,
                effect=payload.effect,
                scope_type=payload.scope_type,
                scope_id=payload.scope_id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid permission assignment request",
            ) from exc
        record_audit_event(
            session,
            event_type="access.permission.assign",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="permission_assignment",
            target_id=assignment.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "principal_type": assignment.principal_type,
                "principal_id": assignment.principal_id,
                "permission": assignment.permission,
                "effect": assignment.effect,
                "scope_type": assignment.scope_type,
                "scope_id": assignment.scope_id,
            },
        )
        session.commit()
        return _permission_assignment_response(assignment)


@router.patch(
    "/users/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
)
def user_password_set_api(
    request: Request,
    user_id: str,
    payload: UserPasswordSetRequest,
    actor: AuthenticatedActor = access_manage_actor_dependency,
) -> None:
    """Replace a user's local password credential for authorized access managers."""

    if not request.app.state.settings.local_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local authentication is disabled",
        )

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        user = _get_user_or_404(session, user_id)
        try:
            set_user_password(session, user, payload.new_password)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid new password",
            ) from exc
        record_audit_event(
            session,
            event_type="access.user.password.set",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="user",
            target_id=user.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"username": user.username},
        )
        session.commit()


def _user_response(user: User) -> UserAccessResponse:
    return UserAccessResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_active=user.is_active,
        created_at=_as_utc(user.created_at),
        updated_at=_as_utc(user.updated_at),
    )


def _machine_credential_response(
    credential: MachineCredential,
) -> MachineCredentialAccessResponse:
    return MachineCredentialAccessResponse(
        id=credential.id,
        name=credential.name,
        client_id=credential.client_id,
        is_active=credential.is_active,
        created_at=_as_utc(credential.created_at),
        updated_at=_as_utc(credential.updated_at),
        revoked_at=_as_utc(credential.revoked_at) if credential.revoked_at else None,
    )


def _group_response(group: Group) -> GroupResponse:
    return GroupResponse(
        id=group.id,
        name=group.name,
        display_name=group.display_name,
        is_protected=group.is_protected,
        created_at=_as_utc(group.created_at),
        updated_at=_as_utc(group.updated_at),
    )


def _membership_response(membership: GroupMembership) -> MembershipResponse:
    return MembershipResponse(
        id=membership.id,
        group_id=membership.group_id,
        principal_type=PrincipalType(membership.principal_type),
        principal_id=membership.principal_id,
        created_at=_as_utc(membership.created_at),
        updated_at=_as_utc(membership.updated_at),
    )


def _permission_assignment_response(
    assignment: PermissionAssignment,
) -> PermissionAssignmentResponse:
    return PermissionAssignmentResponse(
        id=assignment.id,
        principal_type=PrincipalType(assignment.principal_type),
        principal_id=assignment.principal_id,
        permission=assignment.permission,
        effect=PermissionEffect(assignment.effect),
        scope_type=assignment.scope_type,
        scope_id=assignment.scope_id,
        created_at=_as_utc(assignment.created_at),
        updated_at=_as_utc(assignment.updated_at),
    )


def _get_group_or_404(session: Session, group_id: str) -> Group:
    group = session.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return group


def _get_user_or_404(session: Session, user_id: str) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _ensure_principal_exists(
    session: Session,
    principal_type: PrincipalType,
    principal_id: str,
) -> None:
    model = {
        PrincipalType.USER: User,
        PrincipalType.GROUP: Group,
        PrincipalType.MACHINE: MachineCredential,
    }[principal_type]
    if session.get(model, principal_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found")


def _duplicate_group_conflict() -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Group name already exists")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None
