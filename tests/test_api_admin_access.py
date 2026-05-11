import json

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.machines import create_machine_credential
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models import (
    AuditLogEvent,
    Base,
    Group,
    GroupMembership,
    PermissionAssignment,
    PermissionEffect,
    PrincipalType,
)

ADMIN_ACCESS_URL = "/api/admin/access"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(
        AppSettings(
            environment=Environment.TEST,
            database_url="sqlite:///:memory:",
            bootstrap_admin_username="admin",
            bootstrap_admin_password="change-me-now-please",  # noqa: S106 - test fixture password
        )
    )
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_user(
    session_factory: sessionmaker[Session],
    *,
    username: str = "alice",
    permission: str | None = "access:manage",
) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username=username,
            display_name=username.title(),
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        if permission is not None:
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user.id,
                permission=permission,
                effect=PermissionEffect.ALLOW,
                scope_type=None,
                scope_id=None,
            )
        session.commit()
        return user.id


def _login(client: TestClient, *, username: str = "alice") -> None:
    response = client.post(
        "/api/auth/session",
        json={"username": username, "password": "correct horse battery staple"},
    )
    assert response.status_code == 200


def _create_machine_credential(
    session_factory: sessionmaker[Session],
    *,
    name: str = "ci-runner",
) -> str:
    with session_factory() as session:
        _raw_secret, credential = create_machine_credential(session, name=name)
        session.commit()
        return credential.id


def test_access_api_requires_access_manage_or_admin_wildcard(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory, username="alice", permission=None)
        _create_user(session_factory, username="admin", permission="admin:*")
        anonymous_client = _client_with_session_factory(session_factory)
        unauthorized_client = _client_with_session_factory(session_factory)
        _login(unauthorized_client)
        admin_client = _client_with_session_factory(session_factory)
        _login(admin_client, username="admin")

        anonymous_response = anonymous_client.get(ADMIN_ACCESS_URL)
        forbidden_response = unauthorized_client.get(ADMIN_ACCESS_URL)
        allowed_response = admin_client.get(ADMIN_ACCESS_URL)

    assert anonymous_response.status_code == 401
    assert forbidden_response.status_code == 403
    assert allowed_response.status_code == 200


def test_access_api_lists_safe_identity_data(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        machine_id = _create_machine_credential(session_factory)
        with session_factory() as session:
            protected_group = Group(
                name="administrators",
                display_name="Administrators",
                is_protected=True,
            )
            custom_group = Group(name="triage", display_name="Triage", is_protected=False)
            session.add_all([protected_group, custom_group])
            session.flush()
            session.add(
                GroupMembership(
                    group_id=custom_group.id,
                    principal_type=PrincipalType.MACHINE,
                    principal_id=machine_id,
                )
            )
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user_id,
                permission="finding:view",
                effect=PermissionEffect.ALLOW,
                scope_type="project",
                scope_id="project-1",
            )
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.get(ADMIN_ACCESS_URL)

    assert response.status_code == 200
    body = response.json()
    assert {user["id"] for user in body["users"]} == {user_id}
    assert {credential["id"] for credential in body["machine_credentials"]} == {machine_id}
    assert {group["name"] for group in body["groups"]} == {"administrators", "triage"}
    assert body["memberships"][0]["principal_type"] == "machine"
    assert body["permission_assignments"][0]["permission"] == "access:manage"
    assert "finding:view" in body["available_permissions"]
    assert "import:upload" in body["available_permissions"]
    serialized = json.dumps(body)
    assert "password_hash" not in serialized
    assert "client_secret" not in serialized
    assert "client_secret_digest" not in serialized
    assert "token_digest" not in serialized


def test_access_api_creates_custom_group_and_rejects_duplicate(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        create_response = client.post(
            f"{ADMIN_ACCESS_URL}/groups",
            json={"name": "reviewers", "display_name": "Reviewers"},
        )
        duplicate_response = client.post(
            f"{ADMIN_ACCESS_URL}/groups",
            json={"name": "reviewers", "display_name": "Duplicate Reviewers"},
        )
        with session_factory() as session:
            group = session.scalar(select(Group).where(Group.name == "reviewers"))
            audit_event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "access.group.create")
            )

    assert create_response.status_code == 201
    assert create_response.json()["name"] == "reviewers"
    assert create_response.json()["is_protected"] is False
    assert duplicate_response.status_code == 409
    assert duplicate_response.json() == {"detail": "Group name already exists"}
    assert group is not None
    assert audit_event is not None
    assert audit_event.metadata_json == {
        "name": "reviewers",
        "display_name": "Reviewers",
        "is_protected": False,
    }


def test_access_api_adds_machine_credential_to_group(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        machine_id = _create_machine_credential(session_factory)
        with session_factory() as session:
            group = Group(name="automation", display_name="Automation", is_protected=False)
            session.add(group)
            session.commit()
            group_id = group.id
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            f"{ADMIN_ACCESS_URL}/memberships",
            json={
                "group_id": group_id,
                "principal_type": "machine",
                "principal_id": machine_id,
            },
        )
        with session_factory() as session:
            membership = session.scalar(select(GroupMembership))
            audit_event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "access.membership.add")
            )

    assert response.status_code == 201
    body = response.json()
    assert body["group_id"] == group_id
    assert body["principal_type"] == "machine"
    assert body["principal_id"] == machine_id
    assert membership is not None
    assert audit_event is not None
    assert audit_event.metadata_json == {
        "group_id": group_id,
        "principal_type": "machine",
        "principal_id": machine_id,
    }


def test_access_api_assigns_allow_and_deny_scoped_permissions(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        allow_response = client.post(
            f"{ADMIN_ACCESS_URL}/permissions",
            json={
                "principal_type": "user",
                "principal_id": user_id,
                "permission": "finding:view",
                "effect": "allow",
                "scope_type": "project",
                "scope_id": "project-1",
            },
        )
        deny_response = client.post(
            f"{ADMIN_ACCESS_URL}/permissions",
            json={
                "principal_type": "user",
                "principal_id": user_id,
                "permission": "finding:view",
                "effect": "deny",
                "scope_type": "project",
                "scope_id": "project-1",
            },
        )
        with session_factory() as session:
            assignments = list(
                session.scalars(
                    select(PermissionAssignment)
                    .where(PermissionAssignment.permission == "finding:view")
                    .order_by(PermissionAssignment.effect)
                )
            )
            audit_events = list(
                session.scalars(
                    select(AuditLogEvent)
                    .where(AuditLogEvent.event_type == "access.permission.assign")
                    .order_by(AuditLogEvent.created_at)
                )
            )

    assert allow_response.status_code == 201
    assert allow_response.json()["effect"] == "allow"
    assert allow_response.json()["scope_type"] == "project"
    assert deny_response.status_code == 201
    assert deny_response.json()["effect"] == "deny"
    assert [assignment.effect for assignment in assignments] == ["allow", "deny"]
    assert [event.metadata_json["effect"] for event in audit_events] == ["allow", "deny"]
