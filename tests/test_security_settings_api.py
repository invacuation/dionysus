from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models import Base
from dionysus.models.audit import AuditLogEvent
from dionysus.models.identity import PermissionEffect, PrincipalType
from dionysus.security.settings import get_security_settings


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(AppSettings(environment=Environment.TEST, database_url="sqlite:///:memory:"))
    app.state.session_factory = session_factory
    return TestClient(app)


def _login_user(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="password",  # noqa: S106 - test fixture password
        )
        assign_permission(
            session,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            permission="admin:*",
            effect=PermissionEffect.ALLOW,
            scope_type=None,
            scope_id=None,
        )
        session.commit()

    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "password"},
    )
    assert response.status_code == 200


def test_security_settings_api_reads_default_settings(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get("/api/admin/security-settings")

    assert response.status_code == 200
    assert response.json() == {
        "force_peer_review_for_status_changes": False,
        "session_idle_timeout_minutes": 30,
        "session_absolute_timeout_minutes": 480,
    }


def test_security_settings_api_updates_global_peer_review_setting_and_audits(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.patch(
            "/api/admin/security-settings",
            json={
                "force_peer_review_for_status_changes": True,
                "session_idle_timeout_minutes": 45,
                "session_absolute_timeout_minutes": 720,
            },
        )
        with session_factory() as session:
            settings = get_security_settings(session)
            event = session.scalar(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "security.settings.update")
            )

    assert response.status_code == 200
    assert response.json() == {
        "force_peer_review_for_status_changes": True,
        "session_idle_timeout_minutes": 45,
        "session_absolute_timeout_minutes": 720,
    }
    assert settings.force_peer_review_for_status_changes is True
    assert settings.session_idle_timeout_minutes == 45
    assert settings.session_absolute_timeout_minutes == 720
    assert event is not None
    assert event.target_type == "app_security_settings"
    assert event.target_id == "default"
    assert event.metadata_json == {
        "changed_fields": [
            "force_peer_review_for_status_changes",
            "session_idle_timeout_minutes",
            "session_absolute_timeout_minutes",
        ],
        "changes": {
            "force_peer_review_for_status_changes": {
                "old": False,
                "new": True,
            },
            "session_idle_timeout_minutes": {
                "old": 30,
                "new": 45,
            },
            "session_absolute_timeout_minutes": {
                "old": 480,
                "new": 720,
            },
        },
    }


def test_security_settings_api_rejects_invalid_session_timeout_values(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        non_positive_response = client.patch(
            "/api/admin/security-settings",
            json={
                "force_peer_review_for_status_changes": False,
                "session_idle_timeout_minutes": 0,
                "session_absolute_timeout_minutes": 480,
            },
        )
        inverted_response = client.patch(
            "/api/admin/security-settings",
            json={
                "force_peer_review_for_status_changes": False,
                "session_idle_timeout_minutes": 60,
                "session_absolute_timeout_minutes": 30,
            },
        )
        with session_factory() as session:
            events = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "security.settings.update")
            ).all()

    assert non_positive_response.status_code == 422
    assert inverted_response.status_code == 422
    assert "session_absolute_timeout_minutes" in inverted_response.text
    assert events == []
