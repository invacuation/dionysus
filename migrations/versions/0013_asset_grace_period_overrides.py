"""asset grace period overrides

Revision ID: 0013_asset_grace_period_overrides
Revises: 0012_drop_bootstrap_locks
Create Date: 2026-05-13 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_asset_grace_period_overrides"
down_revision: str | None = "0012_drop_bootstrap_locks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add nullable asset grace-period override fields.

    Returns:
        None.
    """

    op.add_column("asset_nodes", sa.Column("grace_period_enabled", sa.Boolean(), nullable=True))
    op.add_column("asset_nodes", sa.Column("grace_period_percent", sa.Integer(), nullable=True))


def downgrade() -> None:
    """Remove nullable asset grace-period override fields.

    Returns:
        None.
    """

    op.drop_column("asset_nodes", "grace_period_percent")
    op.drop_column("asset_nodes", "grace_period_enabled")
