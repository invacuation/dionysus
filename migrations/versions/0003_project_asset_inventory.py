"""project asset inventory tables

Revision ID: 0003_project_asset_inventory
Revises: 0002_machine_refresh_tokens
Create Date: 2026-05-07 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_project_asset_inventory"
down_revision: str | None = "0002_machine_refresh_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create project and asset inventory tables.

    Returns:
        None.
    """

    op.create_table(
        "projects",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("slug", sa.String(length=150), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sla_tracking_enabled", sa.Boolean(), nullable=False),
        sa.Column("sla_reporting_enabled", sa.Boolean(), nullable=False),
        sa.Column("grace_period_enabled", sa.Boolean(), nullable=False),
        sa.Column("grace_period_percent", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
    )
    op.create_index(op.f("ix_projects_slug"), "projects", ["slug"], unique=True)
    op.create_table(
        "asset_nodes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("parent_id", sa.String(), nullable=True),
        sa.Column("node_type", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("target_ref", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("sla_tracking_enabled", sa.Boolean(), nullable=True),
        sa.Column("sla_reporting_enabled", sa.Boolean(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "node_type in ("
            "'folder', 'branch', 'release', 'tag', 'container_image', "
            "'manifest', 'file', 'scan_target', 'other'"
            ")",
            name=op.f("ck_asset_nodes_node_type"),
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["asset_nodes.id"],
            name=op.f("fk_asset_nodes_parent_id_asset_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_asset_nodes_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_nodes")),
        sa.UniqueConstraint("project_id", "path", name=op.f("uq_asset_nodes_project_path")),
        sa.UniqueConstraint(
            "project_id",
            "parent_id",
            "name",
            name=op.f("uq_asset_nodes_project_parent_name"),
        ),
    )
    op.create_index(
        op.f("ix_asset_nodes_node_type"),
        "asset_nodes",
        ["node_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_nodes_parent_id"),
        "asset_nodes",
        ["parent_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_nodes_project_parent",
        "asset_nodes",
        ["project_id", "parent_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_nodes_project_id"),
        "asset_nodes",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_nodes_unique_sibling_name",
        "asset_nodes",
        ["project_id", sa.text("coalesce(parent_id, '__root__')"), "name"],
        unique=True,
    )


def downgrade() -> None:
    """Drop project and asset inventory tables.

    Returns:
        None.
    """

    op.execute("DROP INDEX IF EXISTS ix_asset_nodes_unique_sibling_name")
    op.drop_index(op.f("ix_asset_nodes_project_id"), table_name="asset_nodes")
    op.drop_index("ix_asset_nodes_project_parent", table_name="asset_nodes")
    op.drop_index(op.f("ix_asset_nodes_parent_id"), table_name="asset_nodes")
    op.drop_index(op.f("ix_asset_nodes_node_type"), table_name="asset_nodes")
    op.drop_table("asset_nodes")
    op.drop_index(op.f("ix_projects_slug"), table_name="projects")
    op.drop_table("projects")
