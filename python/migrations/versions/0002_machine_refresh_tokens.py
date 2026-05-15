"""machine refresh token table

Revision ID: 0002_machine_refresh_tokens
Revises: 0001_identity
Create Date: 2026-05-07 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_machine_refresh_tokens"
down_revision: str | None = "0001_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the machine refresh token table.

    Returns:
        None.
    """

    op.create_table(
        "machine_refresh_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("machine_credential_id", sa.String(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_credential_id"],
            ["machine_credentials.id"],
            name=op.f("fk_machine_refresh_tokens_machine_credential_id_machine_credentials"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_refresh_tokens")),
    )
    op.create_index(
        op.f("ix_machine_refresh_tokens_machine_credential_id"),
        "machine_refresh_tokens",
        ["machine_credential_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_machine_refresh_tokens_token_digest"),
        "machine_refresh_tokens",
        ["token_digest"],
        unique=True,
    )


def downgrade() -> None:
    """Drop the machine refresh token table.

    Returns:
        None.
    """

    op.drop_index(
        op.f("ix_machine_refresh_tokens_token_digest"),
        table_name="machine_refresh_tokens",
    )
    op.drop_index(
        op.f("ix_machine_refresh_tokens_machine_credential_id"),
        table_name="machine_refresh_tokens",
    )
    op.drop_table("machine_refresh_tokens")
