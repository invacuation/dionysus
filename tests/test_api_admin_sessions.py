from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.sessions import create_session
from dionysus.identity.users import create_user
from dionysus.models import AuditLogEvent, Base, User, UserSession
from dionysus.models.identity import PermissionEffect, PrincipalType

ADMIN_SESSIONS_URL = "/api/admin/sessions"


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
    display_name: str = "Alice",
) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username=username,
            display_name=display_name,
            password="correct horse battery staple",  # noqa: S106 - test fixture password
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
        return user.id


def _login(client: TestClient) -> str:
    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()["session_id"]


def _create_stored_session(
    session_factory: sessionmaker[Session],
    *,
    user_id: str,
    now: datetime,
    user_agent: str,
    ip_address: str,
) -> str:
    with session_factory() as session:
        owner = session.get(User, user_id)
        assert owner is not None
        _raw_token, session_record = create_session(
            session,
            user=owner,
            now=now,
            idle_timeout_minutes=30,
            absolute_timeout_minutes=120,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        session.commit()
        return session_record.id


def _assert_safe_session(body: dict[str, object]) -> None:
    assert set(body) == {
        "id",
        "user_id",
        "username",
        "display_name",
        "ip_address",
        "user_agent",
        "created_at",
        "last_seen_at",
        "idle_expires_at",
        "expires_at",
        "revoked_at",
        "active",
    }
    assert "token" not in body
    assert "token_digest" not in body


def test_admin_sessions_list_returns_active_and_revoked_sessions_newest_first(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        current_session_id = _login(client)
        with session_factory() as session:
            current_session = session.get(UserSession, current_session_id)
            assert current_session is not None
            current_session.created_at = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
            current_session.last_seen_at = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
            current_session.idle_expires_at = datetime(2026, 12, 1, 12, 30, tzinfo=UTC)
            current_session.expires_at = datetime(2026, 12, 1, 14, 0, tzinfo=UTC)
            session.commit()
        older_session_id = _create_stored_session(
            session_factory,
            user_id=user_id,
            now=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            user_agent="Older browser",
            ip_address="198.51.100.10",
        )
        with session_factory() as session:
            older_session = session.get(UserSession, older_session_id)
            assert older_session is not None
            older_session.created_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
            older_session.revoked_at = datetime(2026, 1, 1, 12, 10, tzinfo=UTC)
            session.commit()

        response = client.get(ADMIN_SESSIONS_URL)

    assert response.status_code == 200
    body = response.json()
    sessions = body["sessions"]
    assert [session["id"] for session in sessions] == [current_session_id, older_session_id]
    for session_body in sessions:
        _assert_safe_session(session_body)
        assert session_body["user_id"] == user_id
        assert session_body["username"] == "alice"
        assert session_body["display_name"] == "Alice"
    assert sessions[0]["active"] is True
    assert sessions[0]["revoked_at"] is None
    assert sessions[1]["active"] is False
    assert sessions[1]["revoked_at"] is not None
    assert sessions[1]["ip_address"] == "198.51.100.10"
    assert sessions[1]["user_agent"] == "Older browser"


def test_admin_sessions_revoke_stamps_revoked_at_and_records_audit_event(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)
        target_session_id = _create_stored_session(
            session_factory,
            user_id=user_id,
            now=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            user_agent="Target browser",
            ip_address="203.0.113.7",
        )

        response = client.post(f"{ADMIN_SESSIONS_URL}/{target_session_id}/revoke")

        with session_factory() as session:
            session_record = session.get(UserSession, target_session_id)
            assert session_record is not None
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "auth.session.revoke")
            ).one()

    assert response.status_code == 200
    body = response.json()
    _assert_safe_session(body)
    assert body["id"] == target_session_id
    assert body["active"] is False
    assert body["revoked_at"] is not None
    assert session_record.revoked_at is not None
    assert event.actor_principal_type == "user"
    assert event.actor_principal_id == user_id
    assert event.actor_display == "Alice"
    assert event.target_type == "session"
    assert event.target_id == target_session_id
    assert event.metadata_json == {
        "revoked_user_id": user_id,
        "revoked_username": "alice",
        "revoked_display_name": "Alice",
    }


def test_admin_sessions_revoke_unknown_session_returns_404(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(f"{ADMIN_SESSIONS_URL}/missing/revoke")

    assert response.status_code == 404
    assert response.json() == {"detail": "Session not found"}


def test_admin_sessions_require_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)

        response = client.get(ADMIN_SESSIONS_URL)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
