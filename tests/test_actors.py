from datetime import UTC, datetime

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from dionysus.config import AppSettings, Environment
from dionysus.identity.actors import (
    ActorType,
    AuthenticatedActor,
    AuthMethod,
    get_authenticated_actor,
    resolve_authenticated_actor,
)
from dionysus.identity.machines import (
    create_machine_credential,
    exchange_machine_client_secret,
    revoke_machine_access_token,
)
from dionysus.identity.sessions import create_session, revoke_session
from dionysus.identity.users import create_user
from dionysus.models.identity import PrincipalType

authenticated_actor_dependency = Depends(get_authenticated_actor)


def test_resolve_authenticated_actor_returns_valid_session_actor(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=None,
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor == AuthenticatedActor(
        actor_type=ActorType.USER,
        actor_id=user.id,
        display_name="Alice",
        principal_type=PrincipalType.USER,
        principal_id=user.id,
        auth_method=AuthMethod.SESSION,
        session_id=session_record.id,
        machine_token_id=None,
        mixed_credentials_present=False,
        bearer_token_present=False,
        session_cookie_present=True,
    )


def test_resolve_authenticated_actor_returns_valid_bearer_actor(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=token_pair.access_token,
        session_cookie=None,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor == AuthenticatedActor(
        actor_type=ActorType.MACHINE,
        actor_id=credential.id,
        display_name="trivy-uploader",
        principal_type=PrincipalType.MACHINE,
        principal_id=credential.id,
        auth_method=AuthMethod.BEARER_TOKEN,
        session_id=None,
        machine_token_id=token_pair.access_token_record.id,
        mixed_credentials_present=False,
        bearer_token_present=True,
        session_cookie_present=False,
    )


def test_resolve_authenticated_actor_uses_bearer_when_both_credentials_present(
    db_session: Session,
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, _session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=token_pair.access_token,
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is not None
    assert actor.actor_type == ActorType.MACHINE
    assert actor.actor_id == credential.id
    assert actor.auth_method == AuthMethod.BEARER_TOKEN
    assert actor.mixed_credentials_present is True
    assert actor.bearer_token_present is True
    assert actor.session_cookie_present is True


def test_resolve_authenticated_actor_rejects_invalid_bearer_without_session_fallback(
    db_session: Session,
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, _session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token="not-a-valid-machine-token",  # noqa: S106
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is None


def test_resolve_authenticated_actor_falls_back_to_session_when_no_bearer(
    db_session: Session,
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, _session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=None,
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is not None
    assert actor.actor_type == ActorType.USER
    assert actor.auth_method == AuthMethod.SESSION


def test_resolve_authenticated_actor_rejects_inactive_session_user(
    db_session: Session,
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, _session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    user.is_active = False
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=None,
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is None


def test_resolve_authenticated_actor_rejects_revoked_machine_token(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None
    revoke_machine_access_token(
        db_session,
        token_pair.access_token_record,
        now=datetime(2026, 5, 7, 12, 1, tzinfo=UTC),
    )
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=token_pair.access_token,
        session_cookie=None,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is None


def test_resolve_authenticated_actor_rejects_expired_or_revoked_session(
    db_session: Session,
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password="password")  # noqa: S106
    session_token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    revoke_session(db_session, session_record, now=datetime(2026, 5, 7, 12, 1, tzinfo=UTC))
    db_session.commit()

    actor = resolve_authenticated_actor(
        db_session,
        bearer_token=None,
        session_cookie=session_token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert actor is None


def test_get_authenticated_actor_raises_401_for_missing_credentials(engine: Engine) -> None:
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    app = FastAPI()
    app.state.session_factory = session_factory
    app.state.settings = AppSettings(environment=Environment.TEST)

    @app.get("/actor")
    def read_actor(
        actor: AuthenticatedActor = authenticated_actor_dependency,
    ) -> dict[str, str]:
        return {"actor_id": actor.actor_id}

    response = TestClient(app).get("/actor")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"
