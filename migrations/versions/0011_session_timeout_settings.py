"""add configurable browser session timeout settings

Revision ID: 0011_session_timeout_settings
Revises: 0010_import_attempt_asset_cascade
Create Date: 2026-05-08 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_session_timeout_settings"
down_revision: str | None = "0010_import_attempt_asset_cascade"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add durable browser session timeout settings.

    Returns:
        None.
    """

    with op.batch_alter_table("app_security_settings") as batch_op:
        batch_op.add_column(sa.Column("session_idle_timeout_minutes", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("session_absolute_timeout_minutes", sa.Integer(), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_app_security_settings_session_idle_timeout_positive",
            "session_idle_timeout_minutes IS NULL OR session_idle_timeout_minutes > 0",
        )
        batch_op.create_check_constraint(
            "ck_app_security_settings_session_absolute_timeout_positive",
            "session_absolute_timeout_minutes IS NULL OR session_absolute_timeout_minutes > 0",
        )
        batch_op.create_check_constraint(
            "ck_app_security_settings_session_absolute_timeout_gte_idle",
            "session_idle_timeout_minutes IS NULL "
            "OR session_absolute_timeout_minutes IS NULL "
            "OR session_absolute_timeout_minutes >= session_idle_timeout_minutes",
        )


def downgrade() -> None:
    """Remove durable browser session timeout settings.

    Returns:
        None.
    """

    with op.batch_alter_table("app_security_settings") as batch_op:
        batch_op.drop_constraint(
            "ck_app_security_settings_session_absolute_timeout_gte_idle",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_app_security_settings_session_absolute_timeout_positive",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_app_security_settings_session_idle_timeout_positive",
            type_="check",
        )
        batch_op.drop_column("session_absolute_timeout_minutes")
        batch_op.drop_column("session_idle_timeout_minutes")
