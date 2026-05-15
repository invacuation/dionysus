"""Import attempt, scan, and vulnerability finding models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dionysus.models.base import Base, TimestampMixin, UUIDPrimaryKey
from dionysus.models.inventory import AssetNode, Project


def _now() -> datetime:
    return datetime.now(UTC)


class ImportStatus(StrEnum):
    """Lifecycle states for a scanner report import attempt."""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class FindingStatus(StrEnum):
    """Workflow states for a persisted vulnerability finding."""

    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"


class FindingStatusChangeState(StrEnum):
    """Review states for requested finding status changes."""

    PENDING = "pending"
    APPLIED = "applied"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class ScannerKind(StrEnum):
    """Scanner integrations supported by finding imports."""

    TRIVY = "trivy"


class ImportAttempt(TimestampMixin, Base):
    """A single scanner report upload or import attempt."""

    __tablename__ = "import_attempts"
    __table_args__ = (
        CheckConstraint("status in ('pending', 'success', 'failed')", name="status"),
        Index("ix_import_attempts_project_status", "project_id", "status"),
        Index("ix_import_attempts_asset_node_status", "asset_node_id", "status"),
        Index("ix_import_attempts_correlation_id", "correlation_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    asset_node_id: Mapped[str | None] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"),
        index=True,
    )
    uploader_principal_type: Mapped[str | None] = mapped_column(String(50), index=True)
    uploader_principal_id: Mapped[str | None] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(20), default=ImportStatus.PENDING, index=True)
    parser_name: Mapped[str] = mapped_column(String(120), index=True)
    sanitized_message: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    project: Mapped[Project] = relationship(back_populates="import_attempts")
    asset_node: Mapped[AssetNode | None] = relationship(back_populates="import_attempts")


class Scan(TimestampMixin, Base):
    """A parsed scanner report bound to one project scan target."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("scanner_kind in ('trivy')", name="scanner_kind"),
        Index("ix_scans_project_target", "project_id", "scan_target_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    scan_target_id: Mapped[str] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"),
        index=True,
    )
    scanner_kind: Mapped[str] = mapped_column(String(50), index=True)
    report_kind: Mapped[str] = mapped_column(String(120), index=True)
    parser_version: Mapped[str] = mapped_column(String(50))
    scan_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scan_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    project: Mapped[Project] = relationship(back_populates="scans")
    scan_target: Mapped[AssetNode] = relationship(back_populates="scans")
    raw_findings: Mapped[list["RawFindingInstance"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class RawFindingInstance(TimestampMixin, Base):
    """A scanner-specific finding occurrence for a project scan target."""

    __tablename__ = "raw_finding_instances"
    __table_args__ = (
        CheckConstraint("scanner_kind in ('trivy')", name="scanner_kind"),
        CheckConstraint(
            "status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="status",
        ),
        UniqueConstraint(
            "scan_target_id",
            "dedupe_key",
            name="uq_raw_finding_instances_scan_target_dedupe_key",
        ),
        Index("ix_raw_finding_instances_project_status", "project_id", "status"),
        Index("ix_raw_finding_instances_scan_status", "scan_id", "status"),
        Index("ix_raw_finding_instances_latest", "scan_target_id", "present_in_latest_scan"),
    )

    id: Mapped[UUIDPrimaryKey]
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    scan_target_id: Mapped[str] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"),
        index=True,
    )
    scanner_kind: Mapped[str] = mapped_column(String(50), index=True)
    scanner_finding_id: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(String(512))
    identifiers_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    primary_identifier: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(50), index=True)
    cvss_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    package_name: Mapped[str | None] = mapped_column(String(255), index=True)
    package_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    artifact_name: Mapped[str | None] = mapped_column(Text)
    artifact_type: Mapped[str | None] = mapped_column(String(120), index=True)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    present_in_latest_scan: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default=FindingStatus.OPEN, index=True)
    references_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    project: Mapped[Project] = relationship()
    scan: Mapped[Scan] = relationship(back_populates="raw_findings")
    scan_target: Mapped[AssetNode] = relationship()
    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    status_change_requests: Mapped[list["FindingStatusChangeRequest"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class ProjectVulnerabilityGroup(TimestampMixin, Base):
    """A project-level vulnerability group deduplicated across scan targets."""

    __tablename__ = "project_vulnerability_groups"
    __table_args__ = (
        CheckConstraint(
            "status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="status",
        ),
        UniqueConstraint(
            "project_id",
            "dedupe_key",
            name="uq_project_vulnerability_groups_project_dedupe_key",
        ),
        Index("ix_project_vulnerability_groups_project_status", "project_id", "status"),
    )

    id: Mapped[UUIDPrimaryKey]
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    primary_identifier: Mapped[str] = mapped_column(String(255), index=True)
    additional_identifiers_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    severity: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50), default=FindingStatus.OPEN, index=True)
    dedupe_key: Mapped[str] = mapped_column(String(512))

    project: Mapped[Project] = relationship(back_populates="vulnerability_groups")


class FindingComment(TimestampMixin, Base):
    """Human or system activity comment attached to a raw finding."""

    __tablename__ = "finding_comments"
    __table_args__ = (
        CheckConstraint(
            "author_principal_type in ('user', 'group', 'machine')",
            name="author_principal_type",
        ),
        CheckConstraint(
            "status_from is null or status_from in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="status_from",
        ),
        CheckConstraint(
            "status_to is null or status_to in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="status_to",
        ),
        Index("ix_finding_comments_finding_created", "finding_id", "created_at"),
        Index("ix_finding_comments_project_created", "project_id", "created_at"),
    )

    id: Mapped[UUIDPrimaryKey]
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("raw_finding_instances.id", ondelete="CASCADE"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    author_principal_type: Mapped[str] = mapped_column(String(20), index=True)
    author_principal_id: Mapped[str] = mapped_column(String(36), index=True)
    body: Mapped[str] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    status_from: Mapped[str | None] = mapped_column(String(50))
    status_to: Mapped[str | None] = mapped_column(String(50))

    project: Mapped[Project] = relationship()
    finding: Mapped[RawFindingInstance] = relationship(back_populates="comments")


class FindingStatusChangeRequest(TimestampMixin, Base):
    """Requested or applied finding status workflow transition."""

    __tablename__ = "finding_status_change_requests"
    __table_args__ = (
        CheckConstraint(
            "requester_principal_type in ('user', 'group', 'machine')",
            name="requester_principal_type",
        ),
        CheckConstraint(
            "reviewer_principal_type is null "
            "or reviewer_principal_type in ('user', 'group', 'machine')",
            name="reviewer_principal_type",
        ),
        CheckConstraint(
            "from_status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="from_status",
        ),
        CheckConstraint(
            "to_status in ("
            "'open', 'accepted_risk', 'false_positive', "
            "'mitigated', 'suppressed', 'fixed'"
            ")",
            name="to_status",
        ),
        CheckConstraint(
            "state in ('pending', 'applied', 'approved', 'rejected', 'cancelled')",
            name="state",
        ),
        Index(
            "ix_finding_status_change_requests_finding_created",
            "finding_id",
            "created_at",
        ),
        Index(
            "ix_finding_status_change_requests_project_state",
            "project_id",
            "state",
        ),
    )

    id: Mapped[UUIDPrimaryKey]
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("raw_finding_instances.id", ondelete="CASCADE"),
        index=True,
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    requester_principal_type: Mapped[str] = mapped_column(String(20), index=True)
    requester_principal_id: Mapped[str] = mapped_column(String(36), index=True)
    reviewer_principal_type: Mapped[str | None] = mapped_column(String(20), index=True)
    reviewer_principal_id: Mapped[str | None] = mapped_column(String(36), index=True)
    from_status: Mapped[str] = mapped_column(String(50))
    to_status: Mapped[str] = mapped_column(String(50))
    state: Mapped[str] = mapped_column(String(20), default=FindingStatusChangeState.PENDING)
    comment: Mapped[str | None] = mapped_column(Text)
    decision_comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship()
    finding: Mapped[RawFindingInstance] = relationship(back_populates="status_change_requests")
