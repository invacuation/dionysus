from datetime import timedelta
from http.cookies import Morsel, SimpleCookie

from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.machines import create_machine_credential, exchange_machine_client_secret
from dionysus.identity.users import create_user
from dionysus.models import AppSecuritySettings, AuditLogEvent, Base, UserSession

SESSION_COOKIE = "dionysus_session"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(
    session_factory: sessionmaker[Session],
    *,
    environment: Environment = Environment.TEST,
) -> TestClient:
    app = create_app(AppSettings(environment=environment, database_url="sqlite:///:memory:"))
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_user(session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="password",  # noqa: S106 - test fixture password
        )
        session.commit()
        return user.id


def _create_machine_access_token(session_factory: sessionmaker[Session]) -> tuple[str, str]:
    with session_factory() as session:
        raw_secret, credential = create_machine_credential(session, name="trivy-uploader")
        token_pair = exchange_machine_client_secret(
            session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=credential.created_at,
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        assert token_pair is not None
        session.commit()
        return credential.id, token_pair.access_token


def _set_cookie(response: Response, name: str) -> Morsel[str]:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie[str] = SimpleCookie()
        cookie.load(header)
        if name in cookie:
            return cookie[name]
    msg = f"Missing Set-Cookie header for {name}"
    raise AssertionError(msg)


def _assert_no_token_material(body: dict[str, object]) -> None:
    forbidden_names = {"token", "access_token", "refresh_token", "bearer_token"}
    assert forbidden_names.isdisjoint(body)
    assert all("token" not in str(value) for value in body.values())


def test_api_login_success_sets_session_cookie_without_returning_token(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)

        response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["actor_type"] == "user"
    assert body["actor_id"] == user_id
    assert body["display_name"] == "Alice"
    assert body["principal_type"] == "user"
    assert body["principal_id"] == user_id
    assert body["auth_method"] == "session"
    assert body["session_id"]
    assert body["machine_token_id"] is None
    assert body["mixed_credentials_present"] is False
    assert body["bearer_token_present"] is False
    assert body["session_cookie_present"] is True
    _assert_no_token_material(body)
    session_cookie = _set_cookie(response, SESSION_COOKIE)
    assert session_cookie.value
    assert session_cookie["httponly"]
    assert session_cookie["samesite"] == "lax"


def test_api_login_uses_configured_security_settings_session_timeouts(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        with session_factory() as session:
            session.add(
                AppSecuritySettings(
                    id="default",
                    session_idle_timeout_minutes=7,
                    session_absolute_timeout_minutes=42,
                )
            )
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )
        with session_factory() as session:
            session_record = session.scalars(select(UserSession)).one()

    assert response.status_code == 200
    assert session_record.expires_at - session_record.idle_expires_at == timedelta(minutes=35)
    assert abs((session_record.expires_at - session_record.created_at).total_seconds() - 2520) < 1


def test_api_login_rejects_invalid_credentials_with_generic_401(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)

        response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "wrong"},
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid username or password"}
        assert SESSION_COOKIE not in response.cookies
        with session_factory() as session:
            assert session.scalars(select(UserSession)).all() == []
            event = session.scalars(select(AuditLogEvent)).one()
            assert event.event_type == "auth.login.failure"
            assert event.actor_principal_type is None
            assert event.metadata_json == {"username": "alice"}


def test_api_login_rejects_form_body(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)

        response = client.post(
            "/api/auth/session",
            data={"username": "alice", "password": "password"},
        )

    assert response.status_code == 422


def test_api_me_returns_session_authenticated_actor(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        login_response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )

        response = client.get("/api/auth/me")

    assert login_response.status_code == 200
    assert response.status_code == 200
    assert response.json() == {
        "actor_type": "user",
        "actor_id": user_id,
        "display_name": "Alice",
        "principal_type": "user",
        "principal_id": user_id,
        "auth_method": "session",
        "session_id": login_response.json()["session_id"],
        "machine_token_id": None,
        "mixed_credentials_present": False,
        "bearer_token_present": False,
        "session_cookie_present": True,
    }


def test_api_me_returns_bearer_authenticated_actor(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        machine_id, access_token = _create_machine_access_token(session_factory)
        client = _client_with_session_factory(session_factory)

        response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["actor_type"] == "machine"
    assert body["actor_id"] == machine_id
    assert body["display_name"] == "trivy-uploader"
    assert body["principal_type"] == "machine"
    assert body["principal_id"] == machine_id
    assert body["auth_method"] == "bearer_token"
    assert body["session_id"] is None
    assert body["machine_token_id"]
    assert body["mixed_credentials_present"] is False
    assert body["bearer_token_present"] is True
    assert body["session_cookie_present"] is False


def test_api_me_uses_bearer_when_both_credentials_are_present(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        machine_id, access_token = _create_machine_access_token(session_factory)
        client = _client_with_session_factory(session_factory)
        login_response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )

        response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert login_response.status_code == 200
    body = response.json()
    assert body["actor_type"] == "machine"
    assert body["actor_id"] == machine_id
    assert body["auth_method"] == "bearer_token"
    assert body["mixed_credentials_present"] is True
    assert body["bearer_token_present"] is True
    assert body["session_cookie_present"] is True


def test_api_logout_revokes_browser_session_and_clears_cookie(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        login_response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )

        response = client.delete("/api/auth/session")

        assert login_response.status_code == 200
        assert response.status_code == 204
        session_cookie = _set_cookie(response, SESSION_COOKIE)
        assert session_cookie.value == ""
        assert session_cookie["max-age"] == "0"
        with session_factory() as session:
            session_record = session.scalars(select(UserSession)).one()
            assert session_record.revoked_at is not None
            events = session.scalars(select(AuditLogEvent).order_by(AuditLogEvent.created_at)).all()
            assert [event.event_type for event in events] == [
                "auth.login.success",
                "auth.logout",
            ]
            assert events[0].actor_principal_id == session_record.user_id
            assert events[0].metadata_json == {"username": "alice"}


def test_api_logout_does_not_revoke_bearer_when_bearer_wins(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        _machine_id, access_token = _create_machine_access_token(session_factory)
        client = _client_with_session_factory(session_factory)
        login_response = client.post(
            "/api/auth/session",
            json={"username": "alice", "password": "password"},
        )

        logout_response = client.delete(
            "/api/auth/session",
            headers={"authorization": f"Bearer {access_token}"},
        )
        bearer_response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {access_token}"},
        )

        assert login_response.status_code == 200
        assert logout_response.status_code == 204
        assert bearer_response.status_code == 200
        assert bearer_response.json()["auth_method"] == "bearer_token"
        with session_factory() as session:
            session_record = session.scalars(select(UserSession)).one()
            assert session_record.revoked_at is not None
