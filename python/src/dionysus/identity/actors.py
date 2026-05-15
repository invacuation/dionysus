"""Unified authenticated actor resolution for browser and machine clients."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from dionysus.identity.cookies import SESSION_COOKIE
from dionysus.identity.machines import verify_machine_access_token
from dionysus.identity.sessions import get_active_session
from dionysus.models.identity import MachineCredential, PrincipalType
from dionysus.security.settings import effective_session_timeout_minutes


class ActorType(StrEnum):
    """Kinds of authenticated actors accepted by application endpoints."""

    USER = "user"
    MACHINE = "machine"


class AuthMethod(StrEnum):
    """Authentication methods that can establish an actor."""

    SESSION = "session"
    BEARER_TOKEN = "bearer_token"  # noqa: S105


@dataclass(frozen=True)
class AuthenticatedActor:
    """Normalized authenticated principal for humans and machine clients."""

    actor_type: ActorType
    actor_id: str
    display_name: str
    principal_type: PrincipalType
    principal_id: str
    auth_method: AuthMethod
    session_id: str | None
    machine_token_id: str | None
    mixed_credentials_present: bool
    bearer_token_present: bool
    session_cookie_present: bool


def resolve_authenticated_actor(
    session: Session,
    *,
    bearer_token: str | None,
    session_cookie: str | None,
    now: datetime,
    idle_timeout_minutes: int,
) -> AuthenticatedActor | None:
    """Resolve request credentials into a normalized actor.

    Bearer access tokens take precedence over browser session cookies. If a
    bearer token is present but invalid, resolution fails without falling back
    to a valid session cookie.

    Args:
        session: The database session used to verify credential material.
        bearer_token: The OAuth-style machine bearer token, or ``None`` when no
            bearer credential was presented.
        session_cookie: The browser session cookie value, or ``None`` when no
            session cookie was presented.
        now: Current UTC time used by credential expiry checks.
        idle_timeout_minutes: Browser session idle timeout used when touching
            valid session credentials.

    Returns:
        The normalized authenticated actor, or ``None`` when authentication
        fails.
    """

    bearer_token_present = bearer_token is not None
    session_cookie_present = session_cookie is not None
    mixed_credentials_present = bearer_token_present and session_cookie_present

    if bearer_token_present:
        machine_token = verify_machine_access_token(session, bearer_token, now=now)
        if machine_token is None:
            return None
        credential = session.get(MachineCredential, machine_token.machine_credential_id)
        if credential is None:
            return None
        return AuthenticatedActor(
            actor_type=ActorType.MACHINE,
            actor_id=credential.id,
            display_name=credential.name,
            principal_type=PrincipalType.MACHINE,
            principal_id=credential.id,
            auth_method=AuthMethod.BEARER_TOKEN,
            session_id=None,
            machine_token_id=machine_token.id,
            mixed_credentials_present=mixed_credentials_present,
            bearer_token_present=True,
            session_cookie_present=session_cookie_present,
        )

    if session_cookie_present:
        session_record = get_active_session(
            session,
            session_cookie,
            now=now,
            idle_timeout_minutes=idle_timeout_minutes,
        )
        if session_record is None:
            return None
        user = session_record.user
        if not user.is_active:
            return None
        return AuthenticatedActor(
            actor_type=ActorType.USER,
            actor_id=user.id,
            display_name=user.display_name,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            auth_method=AuthMethod.SESSION,
            session_id=session_record.id,
            machine_token_id=None,
            mixed_credentials_present=False,
            bearer_token_present=False,
            session_cookie_present=True,
        )

    return None


def parse_bearer_authorization(value: str | None) -> str | None:
    """Extract a bearer token from an Authorization header.

    Args:
        value: The raw Authorization header value.

    Returns:
        The bearer token string when a Bearer credential is present, an empty
        string for a malformed empty Bearer credential, or ``None`` when the
        header is absent or uses another scheme.
    """

    if value is None:
        return None
    scheme, separator, credentials = value.partition(" ")
    if scheme.lower() != "bearer":
        return None
    if not separator:
        return ""
    return credentials.strip()


def _unauthenticated() -> HTTPException:
    """Return the HTTP error raised for missing or invalid credentials."""

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_authenticated_actor(request: Request) -> AuthenticatedActor:
    """FastAPI dependency returning the authenticated request actor.

    Args:
        request: The incoming FastAPI request carrying headers, cookies, and
            application state.

    Returns:
        The normalized authenticated actor.

    Raises:
        HTTPException: If no valid browser session or machine bearer token is
            available.
    """

    session_factory = request.app.state.session_factory
    settings = request.app.state.settings
    bearer_token = parse_bearer_authorization(request.headers.get("authorization"))
    session_cookie = request.cookies.get(SESSION_COOKIE)

    if bearer_token is None and session_cookie is None:
        raise _unauthenticated()

    with session_factory() as db_session:
        idle_timeout_minutes, _absolute_timeout_minutes = effective_session_timeout_minutes(
            db_session,
            default_idle_timeout_minutes=settings.session_idle_timeout_minutes,
            default_absolute_timeout_minutes=settings.session_absolute_timeout_minutes,
        )
        actor = resolve_authenticated_actor(
            db_session,
            bearer_token=bearer_token,
            session_cookie=session_cookie,
            now=datetime.now(UTC),
            idle_timeout_minutes=idle_timeout_minutes,
        )
        if actor is None:
            raise _unauthenticated()
        db_session.commit()
        return actor
