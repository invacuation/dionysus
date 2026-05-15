"""peer review settings

Revision ID: 0009_peer_review_settings
Revises: 0008_audit_log
Create Date: 2026-05-08 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_peer_review_settings"
down_revision: str | None = "0008_audit_log"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add global and project peer-review settings.

    Returns:
        None.
    """

    op.add_column(
        "projects",
        sa.Column(
            "require_peer_review_for_status_changes",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.create_table(
        "app_security_settings",
        sa.Column("id", sa.String(length=50), nullable=False),
        sa.Column(
            "force_peer_review_for_status_changes",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_security_settings")),
    )


def downgrade() -> None:
    """Remove global and project peer-review settings.

    Returns:
        None.
    """

    op.drop_table("app_security_settings")
    op.drop_column("projects", "require_peer_review_for_status_changes")
