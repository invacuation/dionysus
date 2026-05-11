"""Identity, credential, session, and permission models."""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dionysus.models.base import Base, TimestampMixin, UUIDPrimaryKey, uuid_str


class PrincipalType(StrEnum):
    """Kinds of principals that can receive memberships or permissions."""

    USER = "user"
    GROUP = "group"
    MACHINE = "machine"


class PermissionEffect(StrEnum):
    """Whether a permission assignment grants or denies access."""

    ALLOW = "allow"
    DENY = "deny"


class User(TimestampMixin, Base):
    """A human account that can sign in and receive permissions."""

    __tablename__ = "users"

    id: Mapped[UUIDPrimaryKey]
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    password_credential: Mapped["UserPasswordCredential | None"] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class UserPasswordCredential(TimestampMixin, Base):
    """A password credential record storing the user's password hash only."""

    __tablename__ = "user_password_credentials"

    id: Mapped[UUIDPrimaryKey]
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)

    user: Mapped[User] = relationship(back_populates="password_credential")


class UserSession(TimestampMixin, Base):
    """An authenticated user session tracked by token digest and expiry times.

    Session rows store token digests rather than raw tokens and include both
    idle and absolute expiration timestamps for session enforcement.
    """

    __tablename__ = "user_sessions"

    id: Mapped[UUIDPrimaryKey]
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="sessions")


class Group(TimestampMixin, Base):
    """A named collection of principals for shared permissions."""

    __tablename__ = "groups"

    id: Mapped[UUIDPrimaryKey]
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    is_protected: Mapped[bool] = mapped_column(Boolean, default=False)


class GroupMembership(TimestampMixin, Base):
    """A membership record linking a user, group, or machine principal to a group."""

    __tablename__ = "group_memberships"
    __table_args__ = (
        CheckConstraint(
            "principal_type in ('user', 'group', 'machine')",
            name="principal_type",
        ),
        UniqueConstraint("group_id", "principal_type", "principal_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    principal_type: Mapped[str] = mapped_column(String(20), index=True)
    principal_id: Mapped[str] = mapped_column(String(36), index=True)


class MachineCredential(TimestampMixin, Base):
    """A machine client credential used for non-human authentication.

    The client secret is stored as a digest and credentials can be revoked
    without deleting their historical record.
    """

    __tablename__ = "machine_credentials"

    id: Mapped[UUIDPrimaryKey]
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=uuid_str)
    client_secret_digest: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MachineToken(TimestampMixin, Base):
    """An issued machine access token tracked by digest and revocation state."""

    __tablename__ = "machine_tokens"

    id: Mapped[UUIDPrimaryKey]
    machine_credential_id: Mapped[str] = mapped_column(
        ForeignKey("machine_credentials.id", ondelete="CASCADE"),
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MachineRefreshToken(TimestampMixin, Base):
    """A rotating machine refresh token stored only as a digest.

    Refresh tokens are longer-lived than access tokens and are rotated each
    time they are exchanged. Revocation timestamps invalidate used or canceled
    refresh tokens while digest-only storage keeps raw bearer material out of
    the database.
    """

    __tablename__ = "machine_refresh_tokens"

    id: Mapped[UUIDPrimaryKey]
    machine_credential_id: Mapped[str] = mapped_column(
        ForeignKey("machine_credentials.id", ondelete="CASCADE"),
        index=True,
    )
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PermissionAssignment(TimestampMixin, Base):
    """A scoped allow or deny permission attached to a principal."""

    __tablename__ = "permission_assignments"
    __table_args__ = (
        CheckConstraint(
            "principal_type in ('user', 'group', 'machine')",
            name="principal_type",
        ),
        CheckConstraint("effect in ('allow', 'deny')", name="effect"),
        Index("ix_permission_assignments_principal", "principal_type", "principal_id"),
        Index("ix_permission_assignments_scope", "scope_type", "scope_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    principal_type: Mapped[str] = mapped_column(String(20), index=True)
    principal_id: Mapped[str] = mapped_column(String(36), index=True)
    permission: Mapped[str] = mapped_column(String(120), index=True)
    effect: Mapped[str] = mapped_column(String(20), index=True)
    scope_type: Mapped[str | None] = mapped_column(String(50), index=True)
    scope_id: Mapped[str | None] = mapped_column(String(36), index=True)
