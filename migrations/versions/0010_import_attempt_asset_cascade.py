"""cascade import attempts when deleting asset nodes

Revision ID: 0010_import_attempt_asset_cascade
Revises: 0009_peer_review_settings
Create Date: 2026-05-08 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_import_attempt_asset_cascade"
down_revision: str | None = "0009_peer_review_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Cascade import attempts tied to deleted asset nodes.

    Returns:
        None.
    """

    with op.batch_alter_table("import_attempts") as batch_op:
        batch_op.drop_constraint(
            "fk_import_attempts_asset_node_id_asset_nodes",
            type_="foreignkey",
        )
        batch_op.create_foreign_key(
            "fk_import_attempts_asset_node_id_asset_nodes",
            "asset_nodes",
            ["asset_node_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    """Restore the previous SET NULL asset-node behavior.

    Returns:
        None.
    """

    with op.batch_alter_table("import_attempts") as batch_op:
        batch_op.drop_constraint(
            "fk_import_attempts_asset_node_id_asset_nodes",
            type_="foreignkey",
        )
        batch_op.create_foreign_key(
            "fk_import_attempts_asset_node_id_asset_nodes",
            "asset_nodes",
            ["asset_node_id"],
            ["id"],
            ondelete="SET NULL",
        )
