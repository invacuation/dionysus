"""Project and asset inventory models."""

from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dionysus.models.base import Base, TimestampMixin, UUIDPrimaryKey

if TYPE_CHECKING:
    from dionysus.models.findings import ImportAttempt, ProjectVulnerabilityGroup, Scan


class AssetNodeType(StrEnum):
    """Kinds of project inventory asset nodes."""

    FOLDER = "folder"
    BRANCH = "branch"
    RELEASE = "release"
    TAG = "tag"
    CONTAINER_IMAGE = "container_image"
    MANIFEST = "manifest"
    FILE = "file"
    SCAN_TARGET = "scan_target"
    OTHER = "other"


class Project(TimestampMixin, Base):
    """A project that owns an asset inventory tree."""

    __tablename__ = "projects"

    id: Mapped[UUIDPrimaryKey]
    slug: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    sla_tracking_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sla_reporting_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    require_peer_review_for_status_changes: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=false(),
        nullable=False,
    )
    grace_period_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    grace_period_percent: Mapped[int] = mapped_column(Integer, default=100)
    critical_sla_days: Mapped[int] = mapped_column(Integer, default=30, server_default="30")
    high_sla_days: Mapped[int] = mapped_column(Integer, default=60, server_default="60")
    medium_sla_days: Mapped[int] = mapped_column(Integer, default=90, server_default="90")
    low_sla_days: Mapped[int] = mapped_column(Integer, default=180, server_default="180")
    unknown_sla_days: Mapped[int] = mapped_column(Integer, default=365, server_default="365")

    assets: Mapped[list["AssetNode"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )
    import_attempts: Mapped[list["ImportAttempt"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )
    vulnerability_groups: Mapped[list["ProjectVulnerabilityGroup"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )


class AssetNode(TimestampMixin, Base):
    """An inventory node inside a project's asset tree."""

    __tablename__ = "asset_nodes"
    __table_args__ = (
        CheckConstraint(
            "node_type in ("
            "'folder', 'branch', 'release', 'tag', 'container_image', "
            "'manifest', 'file', 'scan_target', 'other'"
            ")",
            name="node_type",
        ),
        UniqueConstraint("project_id", "path", name="uq_asset_nodes_project_path"),
        UniqueConstraint(
            "project_id",
            "parent_id",
            "name",
            name="uq_asset_nodes_project_parent_name",
        ),
        Index("ix_asset_nodes_project_parent", "project_id", "parent_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"),
        index=True,
    )
    node_type: Mapped[str] = mapped_column(String(50), index=True)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(Text)
    target_ref: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sla_tracking_enabled: Mapped[bool | None] = mapped_column(Boolean)
    sla_reporting_enabled: Mapped[bool | None] = mapped_column(Boolean)
    grace_period_enabled: Mapped[bool | None] = mapped_column(Boolean)
    grace_period_percent: Mapped[int | None] = mapped_column(Integer)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    project: Mapped[Project] = relationship(back_populates="assets")
    parent: Mapped["AssetNode | None"] = relationship(
        back_populates="children",
        remote_side="AssetNode.id",
    )
    children: Mapped[list["AssetNode"]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
    )
    import_attempts: Mapped[list["ImportAttempt"]] = relationship(
        back_populates="asset_node",
        cascade="all, delete-orphan",
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="scan_target",
        cascade="all, delete-orphan",
    )


Index(
    "ix_asset_nodes_unique_sibling_name",
    AssetNode.project_id,
    func.coalesce(AssetNode.parent_id, "__root__"),
    AssetNode.name,
    unique=True,
)
