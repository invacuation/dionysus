"""finding comments and status workflow

Revision ID: 0007_finding_workflow
Revises: 0006_bootstrap_locks
Create Date: 2026-05-08 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_finding_workflow"
down_revision: str | None = "0006_bootstrap_locks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FINDING_STATUS_CHECK = (
    "'open', 'accepted_risk', 'false_positive', 'mitigated', 'suppressed', 'fixed'"
)


def upgrade() -> None:
    """Create finding activity and status workflow tables.

    Returns:
        None.
    """

    op.create_table(
        "finding_comments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("author_principal_type", sa.String(length=20), nullable=False),
        sa.Column("author_principal_id", sa.String(length=36), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("status_from", sa.String(length=50), nullable=True),
        sa.Column("status_to", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "author_principal_type in ('user', 'group', 'machine')",
            name=op.f("ck_finding_comments_author_principal_type"),
        ),
        sa.CheckConstraint(
            f"status_from is null or status_from in ({_FINDING_STATUS_CHECK})",
            name=op.f("ck_finding_comments_status_from"),
        ),
        sa.CheckConstraint(
            f"status_to is null or status_to in ({_FINDING_STATUS_CHECK})",
            name=op.f("ck_finding_comments_status_to"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["raw_finding_instances.id"],
            name=op.f("fk_finding_comments_finding_id_raw_finding_instances"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_finding_comments_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_comments")),
    )
    op.create_index(
        op.f("ix_finding_comments_author_principal_id"),
        "finding_comments",
        ["author_principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_comments_author_principal_type"),
        "finding_comments",
        ["author_principal_type"],
        unique=False,
    )
    op.create_index(
        "ix_finding_comments_finding_created",
        "finding_comments",
        ["finding_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_comments_finding_id"),
        "finding_comments",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_comments_is_system"),
        "finding_comments",
        ["is_system"],
        unique=False,
    )
    op.create_index(
        "ix_finding_comments_project_created",
        "finding_comments",
        ["project_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_comments_project_id"),
        "finding_comments",
        ["project_id"],
        unique=False,
    )

    op.create_table(
        "finding_status_change_requests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("requester_principal_type", sa.String(length=20), nullable=False),
        sa.Column("requester_principal_id", sa.String(length=36), nullable=False),
        sa.Column("reviewer_principal_type", sa.String(length=20), nullable=True),
        sa.Column("reviewer_principal_id", sa.String(length=36), nullable=True),
        sa.Column("from_status", sa.String(length=50), nullable=False),
        sa.Column("to_status", sa.String(length=50), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("decision_comment", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "requester_principal_type in ('user', 'group', 'machine')",
            name=op.f("ck_finding_status_change_requests_requester_principal_type"),
        ),
        sa.CheckConstraint(
            "reviewer_principal_type is null "
            "or reviewer_principal_type in ('user', 'group', 'machine')",
            name=op.f("ck_finding_status_change_requests_reviewer_principal_type"),
        ),
        sa.CheckConstraint(
            f"from_status in ({_FINDING_STATUS_CHECK})",
            name=op.f("ck_finding_status_change_requests_from_status"),
        ),
        sa.CheckConstraint(
            f"to_status in ({_FINDING_STATUS_CHECK})",
            name=op.f("ck_finding_status_change_requests_to_status"),
        ),
        sa.CheckConstraint(
            "state in ('pending', 'applied', 'approved', 'rejected', 'cancelled')",
            name=op.f("ck_finding_status_change_requests_state"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["raw_finding_instances.id"],
            name=op.f("fk_finding_status_change_requests_finding_id_raw_finding_instances"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_finding_status_change_requests_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_status_change_requests")),
    )
    op.create_index(
        "ix_finding_status_change_requests_finding_created",
        "finding_status_change_requests",
        ["finding_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_finding_id"),
        "finding_status_change_requests",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_finding_status_change_requests_project_state",
        "finding_status_change_requests",
        ["project_id", "state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_project_id"),
        "finding_status_change_requests",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_requester_principal_id"),
        "finding_status_change_requests",
        ["requester_principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_requester_principal_type"),
        "finding_status_change_requests",
        ["requester_principal_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_reviewer_principal_id"),
        "finding_status_change_requests",
        ["reviewer_principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_status_change_requests_reviewer_principal_type"),
        "finding_status_change_requests",
        ["reviewer_principal_type"],
        unique=False,
    )


def downgrade() -> None:
    """Drop finding activity and status workflow tables.

    Returns:
        None.
    """

    op.drop_index(
        op.f("ix_finding_status_change_requests_reviewer_principal_type"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        op.f("ix_finding_status_change_requests_reviewer_principal_id"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        op.f("ix_finding_status_change_requests_requester_principal_type"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        op.f("ix_finding_status_change_requests_requester_principal_id"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        op.f("ix_finding_status_change_requests_project_id"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        "ix_finding_status_change_requests_project_state",
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        op.f("ix_finding_status_change_requests_finding_id"),
        table_name="finding_status_change_requests",
    )
    op.drop_index(
        "ix_finding_status_change_requests_finding_created",
        table_name="finding_status_change_requests",
    )
    op.drop_table("finding_status_change_requests")

    op.drop_index(op.f("ix_finding_comments_project_id"), table_name="finding_comments")
    op.drop_index("ix_finding_comments_project_created", table_name="finding_comments")
    op.drop_index(op.f("ix_finding_comments_is_system"), table_name="finding_comments")
    op.drop_index(op.f("ix_finding_comments_finding_id"), table_name="finding_comments")
    op.drop_index("ix_finding_comments_finding_created", table_name="finding_comments")
    op.drop_index(
        op.f("ix_finding_comments_author_principal_type"),
        table_name="finding_comments",
    )
    op.drop_index(
        op.f("ix_finding_comments_author_principal_id"),
        table_name="finding_comments",
    )
    op.drop_table("finding_comments")
