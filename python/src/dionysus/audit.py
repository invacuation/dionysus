"""Service helpers for recording append-only audit events."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy.orm import Session

from dionysus.models.audit import AuditLogEvent

_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "authorization",
    "client_secret",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
}
_LARGE_SENSITIVE_KEYS = {
    "raw_report",
    "report",
    "report_payload",
    "stack",
    "stack_trace",
    "stacktrace",
    "traceback",
}


def record_audit_event(
    session: Session,
    *,
    event_type: str,
    actor_principal_type: str | None = None,
    actor_principal_id: str | None = None,
    actor_display: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    project_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> AuditLogEvent:
    """Record one sanitized audit event in the caller's transaction.

    Args:
        session: SQLAlchemy session used for persistence.
        event_type: Stable dotted event type describing what happened.
        actor_principal_type: Optional principal type for the actor.
        actor_principal_id: Optional principal ID for the actor.
        actor_display: Optional human-readable actor name.
        target_type: Optional domain type affected by the event.
        target_id: Optional domain ID affected by the event.
        project_id: Optional project ID associated with the event.
        ip_address: Optional request client IP address.
        user_agent: Optional request user agent.
        metadata: Optional event-specific safe metadata.

    Returns:
        The pending ``AuditLogEvent`` model.

    Raises:
        ValueError: If ``event_type`` is blank.
    """

    normalized_event_type = event_type.strip()
    if not normalized_event_type:
        raise ValueError("event_type is required")

    event = AuditLogEvent(
        event_type=normalized_event_type,
        actor_principal_type=str(actor_principal_type) if actor_principal_type else None,
        actor_principal_id=actor_principal_id,
        actor_display=actor_display,
        target_type=target_type,
        target_id=target_id,
        project_id=project_id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_json=_sanitize_metadata(metadata or {}),
    )
    session.add(event)
    return event


def _sanitize_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Return metadata with obvious sensitive or oversized values redacted."""

    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key)
        if _is_sensitive_key(key_text):
            sanitized[key_text] = _REDACTED
            continue
        sanitized[key_text] = _sanitize_value(value)
    return sanitized


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _sanitize_metadata(value)
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_sanitize_value(item) for item in value]
    return str(value)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_").replace(" ", "_")
    if normalized in _LARGE_SENSITIVE_KEYS:
        return True
    return any(part in _SENSITIVE_KEYS for part in normalized.split("_"))
