from typing import cast

import pytest
from sqlalchemy import DateTime, MetaData, String, Table, create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from dionysus.models import MachineRefreshToken as ExportedMachineRefreshToken
from dionysus.models import PermissionEffect as ExportedPermissionEffect
from dionysus.models import PrincipalType as ExportedPrincipalType
from dionysus.models.base import Base, TimestampMixin, uuid_str
from dionysus.models.identity import (
    Group,
    GroupMembership,
    MachineCredential,
    MachineRefreshToken,
    MachineToken,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
    User,
    UserPasswordCredential,
    UserSession,
)


class TimestampedThing(TimestampMixin, Base):
    __tablename__ = "identity_test_timestamped_things"

    id: Mapped[str] = mapped_column(String, primary_key=True)


def test_model_metadata_uses_naming_conventions() -> None:
    metadata: MetaData = Base.metadata

    assert metadata.naming_convention["pk"] == "pk_%(table_name)s"
    assert (
        metadata.naming_convention["fk"]
        == "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
    )


def test_uuid_helper_returns_non_empty_string() -> None:
    value = uuid_str()

    assert isinstance(value, str)
    assert len(value) >= 32


def test_timestamp_mixin_columns_are_timezone_aware() -> None:
    created_at_type = TimestampedThing.__table__.c.created_at.type
    updated_at_type = TimestampedThing.__table__.c.updated_at.type

    assert isinstance(created_at_type, DateTime)
    assert isinstance(updated_at_type, DateTime)
    assert created_at_type.timezone is True
    assert updated_at_type.timezone is True


def test_identity_models_create_expected_tables() -> None:
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(engine)

    table_names = set(inspect(engine).get_table_names())
    assert {
        "users",
        "user_password_credentials",
        "user_sessions",
        "groups",
        "group_memberships",
        "machine_credentials",
        "machine_refresh_tokens",
        "machine_tokens",
        "permission_assignments",
    }.issubset(table_names)


def test_identity_model_table_names_are_stable() -> None:
    assert User.__tablename__ == "users"
    assert UserPasswordCredential.__tablename__ == "user_password_credentials"
    assert UserSession.__tablename__ == "user_sessions"
    assert Group.__tablename__ == "groups"
    assert GroupMembership.__tablename__ == "group_memberships"
    assert MachineCredential.__tablename__ == "machine_credentials"
    assert MachineRefreshToken.__tablename__ == "machine_refresh_tokens"
    assert MachineToken.__tablename__ == "machine_tokens"
    assert PermissionAssignment.__tablename__ == "permission_assignments"


def test_identity_enums_are_exported_from_models_package() -> None:
    assert ExportedPrincipalType is PrincipalType
    assert ExportedPermissionEffect is PermissionEffect
    assert ExportedMachineRefreshToken is MachineRefreshToken


@pytest.mark.parametrize(
    ("table", "values"),
    [
        (
            GroupMembership.__table__,
            {
                "group_id": "group-1",
                "principal_type": "service-account",
                "principal_id": "principal-1",
            },
        ),
        (
            PermissionAssignment.__table__,
            {
                "principal_type": "service-account",
                "principal_id": "principal-1",
                "permission": "projects.read",
                "effect": PermissionEffect.ALLOW,
            },
        ),
        (
            PermissionAssignment.__table__,
            {
                "principal_type": PrincipalType.USER,
                "principal_id": "principal-1",
                "permission": "projects.read",
                "effect": "maybe",
            },
        ),
    ],
)
def test_identity_permission_enum_columns_reject_invalid_values(table, values) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with engine.begin() as connection:
        if table is GroupMembership.__table__:
            group_table = cast("Table", Group.__table__)
            connection.execute(
                group_table.insert().values(
                    id="group-1",
                    name="admins",
                    display_name="Admins",
                )
            )

        with pytest.raises(IntegrityError):
            connection.execute(table.insert().values(**values))
