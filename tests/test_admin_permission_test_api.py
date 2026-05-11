from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models import Base
from dionysus.models.identity import (
    Group,
    GroupMembership,
    PermissionEffect,
    PrincipalType,
)

ADMIN_PERMISSION_TEST_URL = "/api/admin/permission-test"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(AppSettings(environment=Environment.TEST, database_url="sqlite:///:memory:"))
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_user(session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        assign_permission(
            session,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            permission="permission:test",
            effect=PermissionEffect.ALLOW,
            scope_type=None,
            scope_id=None,
        )
        session.commit()
        return user.id


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200


def test_admin_permission_test_returns_direct_allow(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user_id,
                permission="project:view",
                effect=PermissionEffect.ALLOW,
                scope_type="project",
                scope_id="project-1",
            )
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            ADMIN_PERMISSION_TEST_URL,
            json={
                "principal_type": "user",
                "principal_id": user_id,
                "permission": "project:view",
                "scope_type": "project",
                "scope_id": "project-1",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "allowed": True,
        "explanation": "direct allow matched project:view on project:project-1",
    }


def test_admin_permission_test_returns_explicit_deny_overriding_group_allow(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            group = Group(name="developers", display_name="Developers")
            session.add(group)
            session.flush()
            session.add(
                GroupMembership(
                    group_id=group.id,
                    principal_type=PrincipalType.USER,
                    principal_id=user_id,
                )
            )
            assign_permission(
                session,
                principal_type=PrincipalType.GROUP,
                principal_id=group.id,
                permission="project:view",
                effect=PermissionEffect.ALLOW,
                scope_type="project",
                scope_id="project-1",
            )
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user_id,
                permission="project:view",
                effect=PermissionEffect.DENY,
                scope_type="project",
                scope_id="project-1",
            )
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            ADMIN_PERMISSION_TEST_URL,
            json={
                "principal_type": "user",
                "principal_id": user_id,
                "permission": "project:view",
                "scope_type": "project",
                "scope_id": "project-1",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert "explicit deny" in body["explanation"]
    assert "developers" in body["explanation"]


def test_admin_permission_test_returns_missing_grant(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            ADMIN_PERMISSION_TEST_URL,
            json={
                "principal_type": "user",
                "principal_id": user_id,
                "permission": "project:delete",
                "scope_type": "project",
                "scope_id": "project-1",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "allowed": False,
        "explanation": (
            "no matching grant for project:delete on project:project-1; group context: none"
        ),
    }
