"""project severity sla fields

Revision ID: 0005_project_sla_fields
Revises: 0004_imports_findings
Create Date: 2026-05-07 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_project_sla_fields"
down_revision: str | None = "0004_imports_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add project-level severity SLA defaults.

    Returns:
        None.
    """

    op.add_column(
        "projects",
        sa.Column(
            "critical_sla_days",
            sa.Integer(),
            server_default="30",
            nullable=False,
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "high_sla_days",
            sa.Integer(),
            server_default="60",
            nullable=False,
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "medium_sla_days",
            sa.Integer(),
            server_default="90",
            nullable=False,
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "low_sla_days",
            sa.Integer(),
            server_default="180",
            nullable=False,
        ),
    )
    op.add_column(
        "projects",
        sa.Column(
            "unknown_sla_days",
            sa.Integer(),
            server_default="365",
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Remove project-level severity SLA defaults.

    Returns:
        None.
    """

    op.drop_column("projects", "unknown_sla_days")
    op.drop_column("projects", "low_sla_days")
    op.drop_column("projects", "medium_sla_days")
    op.drop_column("projects", "high_sla_days")
    op.drop_column("projects", "critical_sla_days")
