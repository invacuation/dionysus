"""JSON API route for testing effective permissions."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.identity.permissions import check_permission
from dionysus.models.identity import PrincipalType

router = APIRouter(prefix="/api/admin/permission-test", tags=["permission-test"])
permission_test_actor_dependency = Depends(require_permission("permission:test"))


class PermissionTestRequest(BaseModel):
    """Request body for resolving a permission check."""

    model_config = ConfigDict(extra="forbid")

    principal_type: PrincipalType
    principal_id: str
    permission: str
    scope_type: str | None = None
    scope_id: str | None = None


class PermissionTestResponse(BaseModel):
    """Response body for an effective permission check."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    explanation: str


@router.post("", response_model=PermissionTestResponse)
def permission_test_api(
    request: Request,
    payload: PermissionTestRequest,
    _actor: AuthenticatedActor = permission_test_actor_dependency,
) -> PermissionTestResponse:
    """Return the effective permission decision for a submitted principal.

    Args:
        request: Incoming request containing application state.
        payload: Principal, permission, and exact scope fields to evaluate.
        _actor: Authorized request actor required for access.

    Returns:
        JSON-serializable permission decision with a concise explanation.

    Raises:
        HTTPException: If authentication fails or the request is internally inconsistent.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        try:
            result = check_permission(
                session,
                principal_type=payload.principal_type,
                principal_id=payload.principal_id,
                permission=payload.permission,
                scope_type=payload.scope_type,
                scope_id=payload.scope_id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid permission test request",
            ) from exc
        return PermissionTestResponse(
            allowed=result.allowed,
            explanation=result.explanation,
        )
