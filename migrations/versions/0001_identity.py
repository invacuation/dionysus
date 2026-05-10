"""identity tables

Revision ID: 0001_identity
Revises:
Create Date: 2026-05-07 10:44:38.378620

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_identity"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "groups",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("is_protected", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_groups")),
    )
    op.create_index(op.f("ix_groups_name"), "groups", ["name"], unique=True)
    op.create_table(
        "machine_credentials",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_secret_digest", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_credentials")),
    )
    op.create_index(
        op.f("ix_machine_credentials_client_id"),
        "machine_credentials",
        ["client_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_machine_credentials_name"),
        "machine_credentials",
        ["name"],
        unique=True,
    )
    op.create_table(
        "permission_assignments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("principal_type", sa.String(length=20), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("permission", sa.String(length=120), nullable=False),
        sa.Column("effect", sa.String(length=20), nullable=False),
        sa.Column("scope_type", sa.String(length=50), nullable=True),
        sa.Column("scope_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "effect in ('allow', 'deny')",
            name=op.f("ck_permission_assignments_effect"),
        ),
        sa.CheckConstraint(
            "principal_type in ('user', 'group', 'machine')",
            name=op.f("ck_permission_assignments_principal_type"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permission_assignments")),
    )
    op.create_index(
        op.f("ix_permission_assignments_effect"),
        "permission_assignments",
        ["effect"],
        unique=False,
    )
    op.create_index(
        op.f("ix_permission_assignments_permission"),
        "permission_assignments",
        ["permission"],
        unique=False,
    )
    op.create_index(
        "ix_permission_assignments_principal",
        "permission_assignments",
        ["principal_type", "principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_permission_assignments_principal_id"),
        "permission_assignments",
        ["principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_permission_assignments_principal_type"),
        "permission_assignments",
        ["principal_type"],
        unique=False,
    )
    op.create_index(
        "ix_permission_assignments_scope",
        "permission_assignments",
        ["scope_type", "scope_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_permission_assignments_scope_id"),
        "permission_assignments",
        ["scope_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_permission_assignments_scope_type"),
        "permission_assignments",
        ["scope_type"],
        unique=False,
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)
    op.create_table(
        "group_memberships",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("principal_type", sa.String(length=20), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["groups.id"],
            name=op.f("fk_group_memberships_group_id_groups"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "principal_type in ('user', 'group', 'machine')",
            name=op.f("ck_group_memberships_principal_type"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_group_memberships")),
        sa.UniqueConstraint(
            "group_id",
            "principal_type",
            "principal_id",
            name=op.f("uq_group_memberships_group_id"),
        ),
    )
    op.create_index(
        op.f("ix_group_memberships_group_id"),
        "group_memberships",
        ["group_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_group_memberships_principal_id"),
        "group_memberships",
        ["principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_group_memberships_principal_type"),
        "group_memberships",
        ["principal_type"],
        unique=False,
    )
    op.create_table(
        "machine_tokens",
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
            name=op.f("fk_machine_tokens_machine_credential_id_machine_credentials"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_tokens")),
    )
    op.create_index(
        op.f("ix_machine_tokens_machine_credential_id"),
        "machine_tokens",
        ["machine_credential_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_machine_tokens_token_digest"),
        "machine_tokens",
        ["token_digest"],
        unique=True,
    )
    op.create_table(
        "user_password_credentials",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_password_credentials_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_password_credentials")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_password_credentials_user_id")),
    )
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
    )
    op.create_index(
        op.f("ix_user_sessions_token_digest"),
        "user_sessions",
        ["token_digest"],
        unique=True,
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_index(op.f("ix_user_sessions_token_digest"), table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_table("user_password_credentials")
    op.drop_index(op.f("ix_machine_tokens_token_digest"), table_name="machine_tokens")
    op.drop_index(op.f("ix_machine_tokens_machine_credential_id"), table_name="machine_tokens")
    op.drop_table("machine_tokens")
    op.drop_index(op.f("ix_group_memberships_principal_type"), table_name="group_memberships")
    op.drop_index(op.f("ix_group_memberships_principal_id"), table_name="group_memberships")
    op.drop_index(op.f("ix_group_memberships_group_id"), table_name="group_memberships")
    op.drop_table("group_memberships")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_permission_assignments_scope_type"), table_name="permission_assignments")
    op.drop_index(op.f("ix_permission_assignments_scope_id"), table_name="permission_assignments")
    op.drop_index("ix_permission_assignments_scope", table_name="permission_assignments")
    op.drop_index(
        op.f("ix_permission_assignments_principal_type"),
        table_name="permission_assignments",
    )
    op.drop_index(
        op.f("ix_permission_assignments_principal_id"),
        table_name="permission_assignments",
    )
    op.drop_index("ix_permission_assignments_principal", table_name="permission_assignments")
    op.drop_index(op.f("ix_permission_assignments_permission"), table_name="permission_assignments")
    op.drop_index(op.f("ix_permission_assignments_effect"), table_name="permission_assignments")
    op.drop_table("permission_assignments")
    op.drop_index(op.f("ix_machine_credentials_name"), table_name="machine_credentials")
    op.drop_index(op.f("ix_machine_credentials_client_id"), table_name="machine_credentials")
    op.drop_table("machine_credentials")
    op.drop_index(op.f("ix_groups_name"), table_name="groups")
    op.drop_table("groups")
