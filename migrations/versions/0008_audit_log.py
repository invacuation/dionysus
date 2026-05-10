"""audit log events

Revision ID: 0008_audit_log
Revises: 0007_finding_workflow
Create Date: 2026-05-08 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_audit_log"
down_revision: str | None = "0007_finding_workflow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create append-only audit log events table.

    Returns:
        None.
    """

    op.create_table(
        "audit_log_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("actor_principal_type", sa.String(length=50), nullable=True),
        sa.Column("actor_principal_id", sa.String(length=36), nullable=True),
        sa.Column("actor_display", sa.String(length=255), nullable=True),
        sa.Column("target_type", sa.String(length=120), nullable=True),
        sa.Column("target_id", sa.String(length=255), nullable=True),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("ip_address", sa.String(length=120), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log_events")),
    )
    op.create_index(
        "ix_audit_log_events_actor",
        "audit_log_events",
        [
            "actor_principal_type",
            "actor_principal_id",
        ],
    )
    op.create_index("ix_audit_log_events_created_at", "audit_log_events", ["created_at"])
    op.create_index("ix_audit_log_events_event_type", "audit_log_events", ["event_type"])
    op.create_index("ix_audit_log_events_project_id", "audit_log_events", ["project_id"])
    op.create_index("ix_audit_log_events_target", "audit_log_events", ["target_type", "target_id"])


def downgrade() -> None:
    """Drop append-only audit log events table.

    Returns:
        None.
    """

    op.drop_index("ix_audit_log_events_target", table_name="audit_log_events")
    op.drop_index("ix_audit_log_events_project_id", table_name="audit_log_events")
    op.drop_index("ix_audit_log_events_event_type", table_name="audit_log_events")
    op.drop_index("ix_audit_log_events_created_at", table_name="audit_log_events")
    op.drop_index("ix_audit_log_events_actor", table_name="audit_log_events")
    op.drop_table("audit_log_events")
