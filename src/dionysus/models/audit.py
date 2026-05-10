"""Append-only audit log persistence models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from dionysus.models.base import Base, UUIDPrimaryKey


def _now() -> datetime:
    return datetime.now(UTC)


class AuditLogEvent(Base):
    """Append-only event describing security-relevant application activity."""

    __tablename__ = "audit_log_events"
    __table_args__ = (
        Index("ix_audit_log_events_event_type", "event_type"),
        Index("ix_audit_log_events_actor", "actor_principal_type", "actor_principal_id"),
        Index("ix_audit_log_events_target", "target_type", "target_id"),
        Index("ix_audit_log_events_project_id", "project_id"),
        Index("ix_audit_log_events_created_at", "created_at"),
    )

    id: Mapped[UUIDPrimaryKey]
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    actor_principal_type: Mapped[str | None] = mapped_column(String(50))
    actor_principal_id: Mapped[str | None] = mapped_column(String(36))
    actor_display: Mapped[str | None] = mapped_column(String(255))
    target_type: Mapped[str | None] = mapped_column(String(120))
    target_id: Mapped[str | None] = mapped_column(String(255))
    project_id: Mapped[str | None] = mapped_column(String(36))
    ip_address: Mapped[str | None] = mapped_column(String(120))
    user_agent: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
