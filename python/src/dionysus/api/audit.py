"""JSON API routes for audit log inspection."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.models.audit import AuditLogEvent

router = APIRouter(prefix="/api/audit-log", tags=["audit"])
audit_log_view_actor_dependency = Depends(require_permission("audit_log:view"))
_MAX_LIMIT = 200


class AuditLogEventResponse(BaseModel):
    """Response body for one audit log event."""

    model_config = ConfigDict(extra="forbid")

    id: str
    event_type: str
    actor_principal_type: str | None
    actor_principal_id: str | None
    actor_display: str | None
    target_type: str | None
    target_id: str | None
    project_id: str | None
    ip_address: str | None
    user_agent: str | None
    metadata: dict[str, Any]
    created_at: datetime


class AuditLogResponse(BaseModel):
    """Response body for audit log list queries."""

    model_config = ConfigDict(extra="forbid")

    event_types: list[str]
    events: list[AuditLogEventResponse]


@router.get("", response_model=AuditLogResponse)
def audit_log_api(
    request: Request,
    _actor: AuthenticatedActor = audit_log_view_actor_dependency,
    event_type: str | None = None,
    project_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    limit: int = Query(default=50, ge=1),
) -> AuditLogResponse:
    """Return latest audit events for authorized callers.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.
        event_type: Optional exact event type filter.
        project_id: Optional exact project ID filter.
        target_type: Optional exact target type filter.
        target_id: Optional exact target ID filter.
        created_from: Optional inclusive ISO datetime lower bound for event creation time.
        created_to: Optional inclusive ISO datetime upper bound for event creation time.
        limit: Maximum number of events to return, clamped to a safe bound.

    Returns:
        JSON-serializable audit events sorted newest first.
    """

    created_from_datetime = _parse_query_datetime("created_from", created_from)
    created_to_datetime = _parse_query_datetime("created_to", created_to)
    if (
        created_from_datetime is not None
        and created_to_datetime is not None
        and created_from_datetime > created_to_datetime
    ):
        raise HTTPException(
            status_code=400,
            detail="created_from must be at or before created_to.",
        )

    statement = select(AuditLogEvent)
    if event_type:
        statement = statement.where(AuditLogEvent.event_type == event_type)
    if project_id:
        statement = statement.where(AuditLogEvent.project_id == project_id)
    if target_type:
        statement = statement.where(AuditLogEvent.target_type == target_type)
    if target_id:
        statement = statement.where(AuditLogEvent.target_id == target_id)
    if created_from_datetime is not None:
        statement = statement.where(AuditLogEvent.created_at >= created_from_datetime)
    if created_to_datetime is not None:
        statement = statement.where(AuditLogEvent.created_at <= created_to_datetime)

    statement = statement.order_by(AuditLogEvent.created_at.desc()).limit(min(limit, _MAX_LIMIT))
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        event_types = list(
            session.scalars(
                select(AuditLogEvent.event_type).distinct().order_by(AuditLogEvent.event_type)
            )
        )
        events = session.scalars(statement).all()
        return AuditLogResponse(
            event_types=event_types,
            events=[_event_response(event) for event in events],
        )


def _event_response(event: AuditLogEvent) -> AuditLogEventResponse:
    return AuditLogEventResponse(
        id=event.id,
        event_type=event.event_type,
        actor_principal_type=event.actor_principal_type,
        actor_principal_id=event.actor_principal_id,
        actor_display=event.actor_display,
        target_type=event.target_type,
        target_id=event.target_id,
        project_id=event.project_id,
        ip_address=event.ip_address,
        user_agent=event.user_agent,
        metadata=_metadata_with_ids(event),
        created_at=_as_utc(event.created_at),
    )


def _parse_query_datetime(field_name: str, value: str | None) -> datetime | None:
    """Parse an audit-log ISO datetime query value as UTC when timezone is omitted."""

    if value is None or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must be a valid ISO datetime.",
        ) from exc
    return _as_utc(parsed)


def _metadata_with_ids(event: AuditLogEvent) -> dict[str, Any]:
    """Return audit metadata enriched with persisted identifier columns.

    Args:
        event: Audit event whose metadata should be exposed.

    Returns:
        A shallow metadata copy with selected ID fields added when absent.
    """

    metadata = dict(event.metadata_json)
    for key, value in (
        ("actor_principal_id", event.actor_principal_id),
        ("target_id", event.target_id),
        ("project_id", event.project_id),
    ):
        if value is not None:
            metadata.setdefault(key, value)
    return metadata


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
