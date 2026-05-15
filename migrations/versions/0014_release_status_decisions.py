"""release status decisions

Revision ID: 0014_release_status_decisions
Revises: 0013_asset_grace_period_overrides
Create Date: 2026-05-15 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_release_status_decisions"
down_revision: str | None = "0013_asset_grace_period_overrides"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FINDING_STATUS_CHECK = (
    "'open', 'accepted_risk', 'false_positive', 'mitigated', 'suppressed', 'fixed'"
)


def upgrade() -> None:
    """Create durable release-line status decisions.

    Returns:
        None.
    """

    op.create_table(
        "finding_release_status_decisions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("release_scope_asset_id", sa.String(), nullable=False),
        sa.Column("release_version_asset_id", sa.String(), nullable=False),
        sa.Column("release_version", sa.String(length=120), nullable=False),
        sa.Column("scanner_kind", sa.String(length=50), nullable=False),
        sa.Column("report_kind", sa.String(length=120), nullable=False),
        sa.Column("finding_identity", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("source_finding_id", sa.String(), nullable=False),
        sa.Column("source_comment_id", sa.String(), nullable=True),
        sa.Column("source_request_id", sa.String(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"status in ({_FINDING_STATUS_CHECK})",
            name=op.f("ck_finding_release_status_decisions_status"),
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_finding_release_status_decisions_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["release_scope_asset_id"],
            ["asset_nodes.id"],
            name=op.f("fk_finding_release_status_decisions_release_scope_asset_id_asset_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["release_version_asset_id"],
            ["asset_nodes.id"],
            name=op.f("fk_finding_release_status_decisions_release_version_asset_id_asset_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_finding_id"],
            ["raw_finding_instances.id"],
            name=op.f(
                "fk_finding_release_status_decisions_source_finding_id_raw_finding_instances"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_comment_id"],
            ["finding_comments.id"],
            name=op.f("fk_finding_release_status_decisions_source_comment_id_finding_comments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_request_id"],
            ["finding_status_change_requests.id"],
            name=op.f(
                "fk_finding_release_status_decisions_source_request_id_"
                "finding_status_change_requests"
            ),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_release_status_decisions")),
        sa.UniqueConstraint(
            "project_id",
            "release_scope_asset_id",
            "release_version_asset_id",
            "scanner_kind",
            "report_kind",
            "finding_identity",
            name=op.f("uq_finding_release_status_decisions_release_identity"),
        ),
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_decided_at"),
        "finding_release_status_decisions",
        ["decided_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_finding_identity"),
        "finding_release_status_decisions",
        ["finding_identity"],
        unique=False,
    )
    op.create_index(
        "ix_finding_release_status_decisions_project_version",
        "finding_release_status_decisions",
        ["project_id", "release_version_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_project_id"),
        "finding_release_status_decisions",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_release_scope_asset_id"),
        "finding_release_status_decisions",
        ["release_scope_asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_finding_release_status_decisions_scope_identity",
        "finding_release_status_decisions",
        ["project_id", "release_scope_asset_id", "scanner_kind", "report_kind", "finding_identity"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_release_version"),
        "finding_release_status_decisions",
        ["release_version"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_release_version_asset_id"),
        "finding_release_status_decisions",
        ["release_version_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_report_kind"),
        "finding_release_status_decisions",
        ["report_kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_scanner_kind"),
        "finding_release_status_decisions",
        ["scanner_kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_source_comment_id"),
        "finding_release_status_decisions",
        ["source_comment_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_source_finding_id"),
        "finding_release_status_decisions",
        ["source_finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_source_request_id"),
        "finding_release_status_decisions",
        ["source_request_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_release_status_decisions_status"),
        "finding_release_status_decisions",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    """Drop durable release-line status decisions.

    Returns:
        None.
    """

    op.drop_index(
        op.f("ix_finding_release_status_decisions_status"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_source_request_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_source_finding_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_source_comment_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_scanner_kind"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_report_kind"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_release_version_asset_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_release_version"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        "ix_finding_release_status_decisions_scope_identity",
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_release_scope_asset_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_project_id"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        "ix_finding_release_status_decisions_project_version",
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_finding_identity"),
        table_name="finding_release_status_decisions",
    )
    op.drop_index(
        op.f("ix_finding_release_status_decisions_decided_at"),
        table_name="finding_release_status_decisions",
    )
    op.drop_table("finding_release_status_decisions")
