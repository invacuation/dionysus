"""Authorization helpers for permission-protected API endpoints."""

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from dionysus.identity.actors import AuthenticatedActor, get_authenticated_actor
from dionysus.identity.bootstrap import ADMIN_PERMISSION
from dionysus.identity.permissions import check_permission

authenticated_actor_dependency = Depends(get_authenticated_actor)


def ensure_actor_permission(
    session: Session,
    *,
    actor: AuthenticatedActor,
    permission: str,
    scope_type: str | None,
    scope_id: str | None,
) -> AuthenticatedActor:
    """Return the actor when the requested permission is authorized.

    Exact permission checks run before the unscoped administrator wildcard so a
    matching explicit deny for the requested permission and scope wins over
    ``admin:*``. The administrator wildcard remains an unscoped superuser grant
    for callers without a matching explicit deny.

    Args:
        session: Database session used to evaluate permissions.
        actor: Authenticated actor requesting access.
        permission: Permission name required by the endpoint.
        scope_type: Optional exact scope type for the permission check.
        scope_id: Optional exact scope identifier for the permission check.

    Returns:
        The authorized actor.

    Raises:
        HTTPException: If the actor lacks permission or has an overriding deny.
        ValueError: If exactly one of ``scope_type`` and ``scope_id`` is set.
    """

    requested_check = check_permission(
        session,
        principal_type=actor.principal_type,
        principal_id=actor.principal_id,
        permission=permission,
        scope_type=scope_type,
        scope_id=scope_id,
    )
    if requested_check.allowed:
        return actor
    if requested_check.denied:
        raise _forbidden()

    admin_check = check_permission(
        session,
        principal_type=actor.principal_type,
        principal_id=actor.principal_id,
        permission=ADMIN_PERMISSION,
        scope_type=None,
        scope_id=None,
    )
    if admin_check.allowed:
        return actor

    raise _forbidden()


def actor_has_permission(
    session: Session,
    *,
    actor: AuthenticatedActor,
    permission: str,
    scope_type: str | None,
    scope_id: str | None,
) -> bool:
    """Return whether an actor has a permission without raising API errors.

    Args:
        session: Database session used to evaluate permissions.
        actor: Authenticated actor requesting access.
        permission: Permission name required by the caller.
        scope_type: Optional exact scope type for the permission check.
        scope_id: Optional exact scope identifier for the permission check.

    Returns:
        ``True`` when the actor has the requested permission, otherwise ``False``.
    """

    try:
        ensure_actor_permission(
            session,
            actor=actor,
            permission=permission,
            scope_type=scope_type,
            scope_id=scope_id,
        )
    except HTTPException:
        return False
    return True


def require_permission(
    permission: str,
    *,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> Callable[[Request, AuthenticatedActor], AuthenticatedActor]:
    """Create a FastAPI dependency requiring a named permission.

    Args:
        permission: Permission name required by the endpoint.
        scope_type: Optional exact scope type for the permission check.
        scope_id: Optional exact scope identifier for the permission check.

    Returns:
        A dependency that returns the authenticated actor after authorization.
    """

    def dependency(
        request: Request,
        actor: AuthenticatedActor = authenticated_actor_dependency,
    ) -> AuthenticatedActor:
        """Authorize the authenticated request actor for one endpoint permission."""

        session_factory = request.app.state.session_factory
        with session_factory() as session:
            return ensure_actor_permission(
                session,
                actor=actor,
                permission=permission,
                scope_type=scope_type,
                scope_id=scope_id,
            )

    return dependency


def _forbidden() -> HTTPException:
    """Return the safe authorization error for denied access."""

    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
