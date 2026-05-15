"""Shared SQLAlchemy model base classes and column types."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from sqlalchemy import DateTime, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

UUIDPrimaryKey = Annotated[str, mapped_column(primary_key=True, default=lambda: uuid_str())]
Timestamp = Annotated[
    datetime,
    mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC)),
]
UpdatedTimestamp = Annotated[
    datetime,
    mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    ),
]


def uuid_str() -> str:
    """Return a random UUID string for model primary keys and client IDs.

    Returns:
        A UUID4 value encoded as a string.
    """

    return str(uuid4())


class Base(DeclarativeBase):
    """Declarative base with stable naming conventions for migrations."""

    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class TimestampMixin:
    """Add created and updated timestamps to a model."""

    created_at: Mapped[Timestamp]
    updated_at: Mapped[UpdatedTimestamp]
