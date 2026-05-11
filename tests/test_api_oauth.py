from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.machines import create_machine_credential, revoke_machine_credential
from dionysus.models import Base, MachineCredential, MachineRefreshToken, MachineToken

BEARER_AUTH_SCHEME = "bearer"
WRONG_CREDENTIAL = "wrong"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(
        AppSettings(
            environment=Environment.TEST,
            database_url="sqlite:///:memory:",
            bootstrap_admin_username="admin",
            bootstrap_admin_password="change-me-now-please",  # noqa: S106 - test fixture password
            machine_access_token_expires_minutes=15,
            machine_refresh_token_expires_minutes=60,
        )
    )
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_machine_credential(
    session_factory: sessionmaker[Session],
    *,
    name: str = "trivy-uploader",
) -> tuple[str, str]:
    with session_factory() as session:
        raw_secret, credential = create_machine_credential(session, name=name)
        client_id = credential.client_id
        session.commit()
        return client_id, raw_secret


def _oauth_token_response(
    client: TestClient,
    *,
    client_id: str,
    client_secret: str,
    grant_type: str = "client_credentials",
):
    return client.post(
        "/api/oauth/token",
        json={
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )


def test_oauth_token_exchanges_client_credentials_for_bearer_pair(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory)
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=client_secret,
        )

        with session_factory() as session:
            access_tokens = session.scalars(select(MachineToken)).all()
            refresh_tokens = session.scalars(select(MachineRefreshToken)).all()

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == BEARER_AUTH_SCHEME
    assert body["expires_in"] == 15 * 60
    assert body["refresh_expires_in"] == 60 * 60
    assert "token_digest" not in body
    assert "client_secret" not in body
    assert body["access_token"] != access_tokens[0].token_digest
    assert body["refresh_token"] != refresh_tokens[0].token_digest
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_oauth_token_rejects_invalid_credentials_with_generic_401(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, _client_secret = _create_machine_credential(session_factory)
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=WRONG_CREDENTIAL,
        )

        with session_factory() as session:
            assert session.scalars(select(MachineToken)).all() == []
            assert session.scalars(select(MachineRefreshToken)).all() == []

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid client credentials"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_oauth_token_rejects_unknown_client_with_same_generic_401(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id="missing",
            client_secret=WRONG_CREDENTIAL,
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid client credentials"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_oauth_token_rejects_unsupported_grant_type(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory)
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=client_secret,
            grant_type="authorization_code",
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Unsupported grant_type"}


def test_oauth_token_accepts_form_encoded_body(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory)
        client = _client_with_session_factory(session_factory)

        response = client.post(
            "/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == BEARER_AUTH_SCHEME
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_oauth_access_token_authenticates_against_api_me(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory)
        client = _client_with_session_factory(session_factory)
        token_response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=client_secret,
        )

        response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {token_response.json()['access_token']}"},
        )

        with session_factory() as session:
            credential = session.scalar(
                select(MachineCredential).where(MachineCredential.client_id == client_id)
            )
            assert credential is not None
            machine_id = credential.id

    assert token_response.status_code == 200
    assert response.status_code == 200
    body = response.json()
    assert body["actor_type"] == "machine"
    assert body["actor_id"] == machine_id
    assert body["auth_method"] == "bearer_token"


def test_oauth_token_rejects_inactive_machine_credential(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory, name="inactive")
        with session_factory() as session:
            credential = session.scalar(
                select(MachineCredential).where(MachineCredential.client_id == client_id)
            )
            assert credential is not None
            credential.is_active = False
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=client_secret,
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid client credentials"}


def test_oauth_token_rejects_revoked_machine_credential(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client_id, client_secret = _create_machine_credential(session_factory, name="revoked")
        with session_factory() as session:
            credential = session.scalar(
                select(MachineCredential).where(MachineCredential.client_id == client_id)
            )
            assert credential is not None
            revoke_machine_credential(
                session,
                credential,
                now=datetime(2026, 5, 8, tzinfo=UTC),
            )
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = _oauth_token_response(
            client,
            client_id=client_id,
            client_secret=client_secret,
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid client credentials"}
