"""JSON API routes for admin import history diagnostics."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.models.findings import ImportAttempt
from dionysus.models.identity import MachineCredential, PrincipalType, User

router = APIRouter(prefix="/api/admin/imports", tags=["admin-imports"])
admin_import_history_actor_dependency = Depends(require_permission("import:history:view"))
_MAX_LIMIT = 200
_SAFE_METADATA_KEYS = {
    "failure_category",
    "finding_count",
    "raw_report_retained",
    "scanner",
    "scanner_guess",
}


class AdminImportAttemptResponse(BaseModel):
    """Response body for one admin-visible import attempt."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    project_name: str
    asset_id: str | None
    asset_name: str | None
    asset_path: str | None
    uploader_principal_type: str | None
    uploader_principal_id: str | None
    uploader_display: str | None
    status: str
    parser_name: str
    sanitized_message: str | None
    correlation_id: str | None
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AdminImportHistoryResponse(BaseModel):
    """Response body for admin import history queries."""

    model_config = ConfigDict(extra="forbid")

    attempts: list[AdminImportAttemptResponse]


@router.get("", response_model=AdminImportHistoryResponse)
def admin_import_history_api(
    request: Request,
    _actor: AuthenticatedActor = admin_import_history_actor_dependency,
    limit: int = Query(default=50, ge=1),
) -> AdminImportHistoryResponse:
    """Return newest sanitized import attempts for authorized admins.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.
        limit: Maximum number of attempts to return, clamped to a safe bound.

    Returns:
        JSON-serializable import attempts sorted newest first.
    """

    statement = (
        select(ImportAttempt)
        .options(selectinload(ImportAttempt.project), selectinload(ImportAttempt.asset_node))
        .order_by(ImportAttempt.created_at.desc())
        .limit(min(limit, _MAX_LIMIT))
    )
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        attempts = session.scalars(statement).all()
        display_names = _uploader_display_names(session, attempts)
        return AdminImportHistoryResponse(
            attempts=[_attempt_response(attempt, display_names) for attempt in attempts],
        )


def _attempt_response(
    attempt: ImportAttempt,
    display_names: dict[tuple[str, str], str],
) -> AdminImportAttemptResponse:
    """Build a safe API response for one import attempt.

    Args:
        attempt: Persisted import attempt with project and asset relationships loaded.
        display_names: Principal display names keyed by principal type and ID.

    Returns:
        Admin response body containing no raw report payload content.
    """

    uploader_key = (
        (attempt.uploader_principal_type, attempt.uploader_principal_id)
        if attempt.uploader_principal_type and attempt.uploader_principal_id
        else None
    )
    return AdminImportAttemptResponse(
        id=attempt.id,
        project_id=attempt.project_id,
        project_name=attempt.project.name,
        asset_id=attempt.asset_node_id,
        asset_name=attempt.asset_node.name if attempt.asset_node else None,
        asset_path=attempt.asset_node.path if attempt.asset_node else None,
        uploader_principal_type=attempt.uploader_principal_type,
        uploader_principal_id=attempt.uploader_principal_id,
        uploader_display=display_names.get(uploader_key) if uploader_key else None,
        status=attempt.status,
        parser_name=attempt.parser_name,
        sanitized_message=attempt.sanitized_message,
        correlation_id=attempt.correlation_id,
        metadata=_safe_metadata(attempt.metadata_json),
        created_at=_as_utc(attempt.created_at),
        updated_at=_as_utc(attempt.updated_at),
    )


def _uploader_display_names(
    session,
    attempts: list[ImportAttempt],
) -> dict[tuple[str, str], str]:
    """Resolve uploader display labels for visible import attempts.

    Args:
        session: SQLAlchemy session used to look up user and machine labels.
        attempts: Import attempts whose uploader principals may need labels.

    Returns:
        Mapping from ``(principal_type, principal_id)`` to a display label.
    """

    user_ids = {
        attempt.uploader_principal_id
        for attempt in attempts
        if attempt.uploader_principal_type == PrincipalType.USER and attempt.uploader_principal_id
    }
    machine_ids = {
        attempt.uploader_principal_id
        for attempt in attempts
        if attempt.uploader_principal_type == PrincipalType.MACHINE
        and attempt.uploader_principal_id
    }
    display_names: dict[tuple[str, str], str] = {}
    if user_ids:
        users = session.scalars(select(User).where(User.id.in_(user_ids))).all()
        display_names.update({(PrincipalType.USER, user.id): user.display_name for user in users})
    if machine_ids:
        credentials = session.scalars(
            select(MachineCredential).where(MachineCredential.id.in_(machine_ids))
        ).all()
        display_names.update(
            {(PrincipalType.MACHINE, credential.id): credential.name for credential in credentials}
        )
    return display_names


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return the allow-listed metadata fields safe for admin diagnostics.

    Args:
        metadata: Raw metadata stored on an import attempt.

    Returns:
        Metadata subset that excludes raw payload names or report content.
    """

    return {key: value for key, value in metadata.items() if key in _SAFE_METADATA_KEYS}


def _as_utc(value: datetime) -> datetime:
    """Normalize a timestamp to timezone-aware UTC.

    Args:
        value: Timestamp from the database.

    Returns:
        Timezone-aware UTC datetime.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
