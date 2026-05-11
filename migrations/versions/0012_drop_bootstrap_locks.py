"""drop bootstrap lock sentinels

Revision ID: 0012_drop_bootstrap_locks
Revises: 0011_session_timeout_settings
Create Date: 2026-05-11 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_drop_bootstrap_locks"
down_revision: str | None = "0011_session_timeout_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Remove obsolete bootstrap lock sentinels.

    Returns:
        None.
    """

    op.drop_index(op.f("ix_bootstrap_locks_name"), table_name="bootstrap_locks")
    op.drop_table("bootstrap_locks")


def downgrade() -> None:
    """Recreate obsolete bootstrap lock sentinels.

    Returns:
        None.
    """

    op.create_table(
        "bootstrap_locks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_bootstrap_locks")),
    )
    op.create_index(op.f("ix_bootstrap_locks_name"), "bootstrap_locks", ["name"], unique=True)
