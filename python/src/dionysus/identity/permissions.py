"""Permission assignment and effective permission checking services."""

from dataclasses import dataclass

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from dionysus.models.identity import (
    Group,
    GroupMembership,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
)

KNOWN_PERMISSIONS: tuple[str, ...] = (
    "access:manage",
    "admin:*",
    "asset:create",
    "asset:delete",
    "asset:update",
    "credential:manage",
    "finding:comment",
    "finding:status_change:approve",
    "finding:status_change:request",
    "finding:view",
    "import:history:view",
    "import:upload",
    "project:create",
    "project:delete",
    "project:update",
    "project:view",
    "report:view",
)


@dataclass(frozen=True)
class PermissionCheck:
    """The outcome and human-readable explanation for a permission check.

    Attributes:
        allowed: Whether the permission check granted access.
        denied: Whether an explicit deny matched the permission check.
        explanation: A concise reason for the decision.
    """

    allowed: bool
    explanation: str
    denied: bool = False


def assign_permission(
    session: Session,
    *,
    principal_type: PrincipalType,
    principal_id: str,
    permission: str,
    effect: PermissionEffect,
    scope_type: str | None,
    scope_id: str | None,
) -> PermissionAssignment:
    """Assign a scoped allow or deny to a principal.

    Existing identical assignments are reused so repeated calls are idempotent.

    Args:
        session: The database session used to persist the assignment.
        principal_type: The kind of principal receiving the assignment.
        principal_id: The identifier of the principal receiving the assignment.
        permission: The permission name to allow or deny.
        effect: Whether the assignment allows or denies the permission.
        scope_type: The optional scope category for scoped permissions.
        scope_id: The optional scope identifier for scoped permissions.

    Returns:
        The existing or newly flushed permission assignment.

    Raises:
        ValueError: If exactly one of ``scope_type`` and ``scope_id`` is set.
    """

    _validate_scope_pair(scope_type, scope_id)
    existing = session.scalar(
        select(PermissionAssignment).where(
            PermissionAssignment.principal_type == principal_type,
            PermissionAssignment.principal_id == principal_id,
            PermissionAssignment.permission == permission,
            PermissionAssignment.effect == effect,
            PermissionAssignment.scope_type == scope_type,
            PermissionAssignment.scope_id == scope_id,
        )
    )
    if existing is not None:
        return existing

    assignment = PermissionAssignment(
        principal_type=principal_type,
        principal_id=principal_id,
        permission=permission,
        effect=effect,
        scope_type=scope_type,
        scope_id=scope_id,
    )
    session.add(assignment)
    session.flush()
    return assignment


def check_permission(
    session: Session,
    *,
    principal_type: PrincipalType,
    principal_id: str,
    permission: str,
    scope_type: str | None,
    scope_id: str | None,
) -> PermissionCheck:
    """Resolve whether a principal has a permission for an exact scope.

    Direct assignments and inherited group assignments are considered together.
    Any matching explicit deny overrides matching allows so operators can safely
    remove access without changing broader group grants.

    Args:
        session: The database session used to read memberships and assignments.
        principal_type: The kind of principal to check.
        principal_id: The identifier of the principal to check.
        permission: The permission name to resolve.
        scope_type: The optional scope category to match exactly.
        scope_id: The optional scope identifier to match exactly.

    Returns:
        A permission check result with the allow decision and explanation.

    Raises:
        ValueError: If exactly one of ``scope_type`` and ``scope_id`` is set.
    """

    _validate_scope_pair(scope_type, scope_id)
    principal_refs = _principal_refs_for_check(session, principal_type, principal_id)
    assignments = _matching_assignments(session, permission, scope_type, scope_id, principal_refs)
    group_ids = [ref_id for ref_type, ref_id in principal_refs if ref_type == PrincipalType.GROUP]

    denies = [
        assignment for assignment in assignments if assignment.effect == PermissionEffect.DENY
    ]
    if denies:
        return PermissionCheck(
            allowed=False,
            explanation=_deny_explanation(session, denies, group_ids),
            denied=True,
        )

    direct_allows = [
        assignment
        for assignment in assignments
        if assignment.effect == PermissionEffect.ALLOW
        and assignment.principal_type == principal_type
        and assignment.principal_id == principal_id
    ]
    if direct_allows:
        return PermissionCheck(
            allowed=True,
            explanation=f"direct allow matched {permission} on {scope_type}:{scope_id}",
        )

    group_allows = [
        assignment for assignment in assignments if assignment.effect == PermissionEffect.ALLOW
    ]
    if group_allows:
        group_names = _group_names(
            session,
            [assignment.principal_id for assignment in group_allows],
        )
        return PermissionCheck(
            allowed=True,
            explanation=(
                f"group allow matched {permission} on {scope_type}:{scope_id}"
                f" via {_format_names(group_names)}"
            ),
        )

    names = _group_names(session, group_ids)
    return PermissionCheck(
        allowed=False,
        explanation=(
            f"no matching grant for {permission} on {scope_type}:{scope_id}; "
            f"group context: {_format_names(names)}"
        ),
    )


def _principal_refs_for_check(
    session: Session,
    principal_type: PrincipalType,
    principal_id: str,
) -> list[tuple[PrincipalType, str]]:
    """Return direct and inherited group principal references for a permission check."""

    refs = [(principal_type, principal_id)]
    seen_groups: set[str] = set()
    pending = [(principal_type, principal_id)]

    while pending:
        current_type, current_id = pending.pop()
        for group_id in _group_ids_for_principal(session, current_type, current_id):
            if group_id in seen_groups:
                continue
            seen_groups.add(group_id)
            group_ref = (PrincipalType.GROUP, group_id)
            refs.append(group_ref)
            pending.append(group_ref)

    return refs


def _group_ids_for_principal(
    session: Session,
    principal_type: PrincipalType,
    principal_id: str,
) -> list[str]:
    """Return groups that directly contain the given principal."""

    return list(
        session.scalars(
            select(GroupMembership.group_id).where(
                GroupMembership.principal_type == principal_type,
                GroupMembership.principal_id == principal_id,
            )
        )
    )


def _matching_assignments(
    session: Session,
    permission: str,
    scope_type: str | None,
    scope_id: str | None,
    principal_refs: list[tuple[PrincipalType, str]],
) -> list[PermissionAssignment]:
    """Return assignments matching the permission, exact scope, and principal set."""

    if not principal_refs:
        return []

    return list(
        session.scalars(
            select(PermissionAssignment).where(
                PermissionAssignment.permission == permission,
                PermissionAssignment.scope_type == scope_type,
                PermissionAssignment.scope_id == scope_id,
                tuple_(
                    PermissionAssignment.principal_type,
                    PermissionAssignment.principal_id,
                ).in_(principal_refs),
            )
        )
    )


def _validate_scope_pair(scope_type: str | None, scope_id: str | None) -> None:
    """Require scope fields to both identify a scope or both be unscoped."""

    if (scope_type is None) != (scope_id is None):
        msg = "scope_type and scope_id must both be set or both be None"
        raise ValueError(msg)


def _deny_explanation(
    session: Session,
    denies: list[PermissionAssignment],
    group_ids: list[str],
) -> str:
    """Build an explanation for denied access that includes group context."""

    deny_sources = []
    for assignment in denies:
        if assignment.principal_type == PrincipalType.GROUP:
            deny_sources.extend(_group_names(session, [assignment.principal_id]))
        else:
            deny_sources.append(f"{assignment.principal_type}:{assignment.principal_id}")

    context_names = _group_names(session, group_ids)
    return (
        f"explicit deny matched from {_format_names(deny_sources)}; "
        f"group context: {_format_names(context_names)}"
    )


def _group_names(session: Session, group_ids: list[str]) -> list[str]:
    """Return stable group names for known group identifiers."""

    if not group_ids:
        return []
    return list(session.scalars(select(Group.name).where(Group.id.in_(group_ids))))


def _format_names(names: list[str]) -> str:
    """Format names for concise permission explanations."""

    return ", ".join(sorted(set(names))) if names else "none"
