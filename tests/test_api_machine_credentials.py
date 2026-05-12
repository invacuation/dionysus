from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from conftest import create_prepared_test_app
from dionysus.identity.machines import create_machine_credential, exchange_machine_client_secret
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models import (
    AuditLogEvent,
    Base,
    MachineRefreshToken,
    MachineToken,
)
from dionysus.models.identity import PermissionEffect, PrincipalType

ADMIN_MACHINE_CREDENTIALS_URL = "/api/admin/machine-credentials"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_prepared_test_app(
        machine_access_token_expires_minutes=15,
        machine_refresh_token_expires_minutes=60,
    )
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
            permission="admin:*",
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


def _create_machine_credential(
    session_factory: sessionmaker[Session],
    *,
    name: str = "trivy-uploader",
) -> tuple[str, str, str]:
    with session_factory() as session:
        raw_secret, credential = create_machine_credential(session, name=name)
        session.commit()
        return credential.id, credential.client_id, raw_secret


def _exchange_machine_token(
    client: TestClient,
    *,
    client_id: str,
    client_secret: str,
):
    return client.post(
        "/api/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )


def _machine_bearer_headers(
    session_factory: sessionmaker[Session],
    *,
    name: str = "automation-admin",
) -> dict[str, str]:
    with session_factory() as session:
        raw_secret, credential = create_machine_credential(session, name=name)
        assign_permission(
            session,
            principal_type=PrincipalType.MACHINE,
            principal_id=credential.id,
            permission="credential:manage",
            effect=PermissionEffect.ALLOW,
            scope_type=None,
            scope_id=None,
        )
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
        return {"authorization": f"Bearer {token_pair.access_token}"}


def _assert_safe_credential(body: dict[str, object]) -> None:
    assert set(body) == {
        "id",
        "name",
        "client_id",
        "is_active",
        "created_by_principal_type",
        "created_by_principal_id",
        "created_by_display",
        "created_at",
        "updated_at",
        "revoked_at",
    }
    assert "client_secret" not in body
    assert "client_secret_digest" not in body


def test_machine_credentials_create_returns_secret_once_and_list_is_safe(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        create_response = client.post(
            ADMIN_MACHINE_CREDENTIALS_URL,
            json={"name": "ci-runner"},
        )
        list_response = client.get(ADMIN_MACHINE_CREDENTIALS_URL)

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["name"] == "ci-runner"
    assert created["client_id"]
    assert created["client_secret"]
    assert created["is_active"] is True
    assert created["revoked_at"] is None
    assert "client_secret_digest" not in created

    assert list_response.status_code == 200
    credentials = list_response.json()["credentials"]
    assert len(credentials) == 1
    assert credentials[0]["id"] == created["id"]
    assert credentials[0]["name"] == "ci-runner"
    assert credentials[0]["created_by_principal_type"] == "user"
    assert credentials[0]["created_by_display"] == "Alice"
    _assert_safe_credential(credentials[0])


def test_machine_credentials_create_duplicate_name_returns_conflict(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        _create_machine_credential(session_factory, name="ci-runner")
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            ADMIN_MACHINE_CREDENTIALS_URL,
            json={"name": "ci-runner"},
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Machine credential name already exists"}


def test_machine_credentials_regenerate_secret_invalidates_old_secret_and_revokes_tokens(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        credential_id, client_id, old_secret = _create_machine_credential(
            session_factory,
            name="ci-runner",
        )
        client = _client_with_session_factory(session_factory)
        _login(client)
        old_token_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=old_secret,
        )

        response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/{credential_id}/regenerate-secret",
            json={"revoke_tokens": True},
        )
        new_secret = response.json()["client_secret"]
        old_secret_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=old_secret,
        )
        new_secret_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=new_secret,
        )
        bearer_response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {old_token_response.json()['access_token']}"},
        )

        with session_factory() as session:
            token = session.scalars(select(MachineToken)).first()
            refresh_token = session.scalars(select(MachineRefreshToken)).first()
            assert token is not None
            assert refresh_token is not None
            assert token.revoked_at is not None
            assert refresh_token.revoked_at is not None

    assert old_token_response.status_code == 200
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == credential_id
    assert body["client_secret"]
    assert body["client_secret"] != old_secret
    assert "client_secret_digest" not in body
    assert old_secret_response.status_code == 401
    assert new_secret_response.status_code == 200
    assert bearer_response.status_code == 401


def test_machine_credentials_regenerate_secret_can_keep_existing_tokens(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        credential_id, client_id, old_secret = _create_machine_credential(
            session_factory,
            name="ci-runner",
        )
        client = _client_with_session_factory(session_factory)
        _login(client)
        old_token_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=old_secret,
        )

        response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/{credential_id}/regenerate-secret",
            json={"revoke_tokens": False},
        )
        new_secret = response.json()["client_secret"]
        old_secret_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=old_secret,
        )
        new_secret_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=new_secret,
        )
        bearer_response = client.get(
            "/api/auth/me",
            headers={"authorization": f"Bearer {old_token_response.json()['access_token']}"},
        )

        with session_factory() as session:
            token = session.scalars(select(MachineToken)).first()
            refresh_token = session.scalars(select(MachineRefreshToken)).first()
            assert token is not None
            assert refresh_token is not None
            assert token.revoked_at is None
            assert refresh_token.revoked_at is None

    assert old_token_response.status_code == 200
    assert response.status_code == 200
    assert old_secret_response.status_code == 401
    assert new_secret_response.status_code == 200
    assert bearer_response.status_code == 200


def test_machine_credentials_revoke_disables_exchange_and_returns_safe_body(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        credential_id, client_id, client_secret = _create_machine_credential(
            session_factory,
            name="ci-runner",
        )
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/{credential_id}/revoke",
            json={"revoke_tokens": True},
        )
        exchange_response = _exchange_machine_token(
            client,
            client_id=client_id,
            client_secret=client_secret,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == credential_id
    assert body["is_active"] is False
    assert body["revoked_at"] is not None
    _assert_safe_credential(body)
    assert exchange_response.status_code == 401


def test_machine_credentials_missing_credential_returns_404(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        regenerate_response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/missing/regenerate-secret",
            json={"revoke_tokens": True},
        )
        revoke_response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/missing/revoke",
            json={"revoke_tokens": True},
        )

    assert regenerate_response.status_code == 404
    assert revoke_response.status_code == 404


def test_machine_credentials_records_sanitized_audit_events(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        client = _client_with_session_factory(session_factory)
        _login(client)

        create_response = client.post(
            ADMIN_MACHINE_CREDENTIALS_URL,
            json={"name": "ci-runner"},
        )
        credential_id = create_response.json()["id"]
        regenerate_response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/{credential_id}/regenerate-secret",
            json={"revoke_tokens": False},
        )
        revoke_response = client.post(
            f"{ADMIN_MACHINE_CREDENTIALS_URL}/{credential_id}/revoke",
            json={"revoke_tokens": True},
        )

        with session_factory() as session:
            events = session.scalars(
                select(AuditLogEvent)
                .where(AuditLogEvent.target_type == "machine_credential")
                .order_by(AuditLogEvent.created_at)
            ).all()

    assert create_response.status_code == 201
    assert regenerate_response.status_code == 200
    assert revoke_response.status_code == 200
    assert [event.event_type for event in events] == [
        "machine_credential.create",
        "machine_credential.regenerate_secret",
        "machine_credential.revoke",
    ]
    for event in events:
        assert event.actor_principal_type == "user"
        assert event.actor_principal_id == user_id
        assert event.actor_display == "Alice"
        assert event.target_id == credential_id
        assert "client_secret" not in event.metadata_json
        assert "client_secret_digest" not in event.metadata_json
    assert events[0].metadata_json == {"name": "ci-runner"}
    assert events[1].metadata_json == {"name": "ci-runner", "revoke_tokens": False}
    assert events[2].metadata_json == {"name": "ci-runner", "revoke_tokens": True}


def test_machine_credentials_require_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)

        response = client.get(ADMIN_MACHINE_CREDENTIALS_URL)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_machine_credentials_allow_machine_bearer_actor(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        headers = _machine_bearer_headers(session_factory)

        response = client.post(
            ADMIN_MACHINE_CREDENTIALS_URL,
            json={"name": "machine-created"},
            headers=headers,
        )

    assert response.status_code == 201
    assert response.json()["name"] == "machine-created"
