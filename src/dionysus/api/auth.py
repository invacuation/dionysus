"""JSON authentication API routes for React clients."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from dionysus.audit import record_audit_event
from dionysus.identity.actors import (
    ActorType,
    AuthenticatedActor,
    AuthMethod,
    get_authenticated_actor,
)
from dionysus.identity.cookies import SESSION_COOKIE, cookies_secure
from dionysus.identity.sessions import create_session, get_active_session, revoke_session
from dionysus.identity.users import authenticate_user
from dionysus.models.identity import PrincipalType
from dionysus.security.settings import effective_session_timeout_minutes

router = APIRouter(prefix="/api/auth", tags=["auth"])
authenticated_actor_dependency = Depends(get_authenticated_actor)


class LoginRequest(BaseModel):
    """Credentials submitted to create a browser session."""

    model_config = ConfigDict(extra="forbid")

    username: str
    password: str


class ActorResponse(BaseModel):
    """Safe normalized metadata for the authenticated actor."""

    model_config = ConfigDict(extra="forbid")

    actor_type: str
    actor_id: str
    display_name: str
    principal_type: str
    principal_id: str
    auth_method: str
    session_id: str | None
    machine_token_id: str | None
    mixed_credentials_present: bool
    bearer_token_present: bool
    session_cookie_present: bool


def _actor_response(actor: AuthenticatedActor) -> ActorResponse:
    return ActorResponse(
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        display_name=actor.display_name,
        principal_type=actor.principal_type,
        principal_id=actor.principal_id,
        auth_method=actor.auth_method,
        session_id=actor.session_id,
        machine_token_id=actor.machine_token_id,
        mixed_credentials_present=actor.mixed_credentials_present,
        bearer_token_present=actor.bearer_token_present,
        session_cookie_present=actor.session_cookie_present,
    )


@router.post("/session", response_model=ActorResponse)
def create_browser_session(
    request: Request,
    credentials: LoginRequest,
    response: Response,
) -> ActorResponse:
    """Authenticate local credentials and create a browser session.

    Args:
        request: Incoming request containing application state and client
            metadata.
        credentials: JSON username and password credentials.
        response: Mutable response used to set the HTTP-only session cookie.

    Returns:
        Safe actor and session metadata for the newly authenticated user.

    Raises:
        HTTPException: If the submitted credentials are invalid.
    """

    session_factory = request.app.state.session_factory
    settings = request.app.state.settings
    now = datetime.now(UTC)
    with session_factory() as db_session:
        user = authenticate_user(db_session, credentials.username, credentials.password)
        if user is None:
            record_audit_event(
                db_session,
                event_type="auth.login.failure",
                ip_address=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                metadata={"username": credentials.username},
            )
            db_session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        idle_timeout_minutes, absolute_timeout_minutes = effective_session_timeout_minutes(
            db_session,
            default_idle_timeout_minutes=settings.session_idle_timeout_minutes,
            default_absolute_timeout_minutes=settings.session_absolute_timeout_minutes,
        )
        raw_token, session_record = create_session(
            db_session,
            user=user,
            now=now,
            idle_timeout_minutes=idle_timeout_minutes,
            absolute_timeout_minutes=absolute_timeout_minutes,
            user_agent=request.headers.get("user-agent"),
            ip_address=_client_host(request),
        )
        record_audit_event(
            db_session,
            event_type="auth.login.success",
            actor_principal_type=PrincipalType.USER,
            actor_principal_id=user.id,
            actor_display=user.display_name,
            target_type="session",
            target_id=session_record.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"username": credentials.username},
        )
        db_session.commit()
        actor = AuthenticatedActor(
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

    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        httponly=True,
        secure=cookies_secure(request),
        samesite="lax",
    )
    return _actor_response(actor)


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_browser_session(request: Request, response: Response) -> Response:
    """Revoke the browser session cookie without touching bearer tokens.

    Args:
        request: Incoming request containing cookies and application state.
        response: Empty response used to clear the browser session cookie.

    Returns:
        An empty 204 response with an expired session cookie.
    """

    raw_token = request.cookies.get(SESSION_COOKIE)
    if raw_token:
        session_factory = request.app.state.session_factory
        settings = request.app.state.settings
        now = datetime.now(UTC)
        with session_factory() as db_session:
            idle_timeout_minutes, _absolute_timeout_minutes = effective_session_timeout_minutes(
                db_session,
                default_idle_timeout_minutes=settings.session_idle_timeout_minutes,
                default_absolute_timeout_minutes=settings.session_absolute_timeout_minutes,
            )
            session_record = get_active_session(
                db_session,
                raw_token,
                now=now,
                idle_timeout_minutes=idle_timeout_minutes,
            )
            if session_record is not None:
                revoke_session(db_session, session_record, now=now)
                record_audit_event(
                    db_session,
                    event_type="auth.logout",
                    actor_principal_type=PrincipalType.USER,
                    actor_principal_id=session_record.user_id,
                    actor_display=session_record.user.display_name,
                    target_type="session",
                    target_id=session_record.id,
                    ip_address=_client_host(request),
                    user_agent=request.headers.get("user-agent"),
                )
                db_session.commit()

    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=cookies_secure(request),
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=ActorResponse)
def current_actor(
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> ActorResponse:
    """Return normalized metadata for the current authenticated actor.

    Args:
        actor: The actor resolved by the unified browser session and machine
            bearer dependency.

    Returns:
        Safe actor metadata for the authenticated caller.
    """

    return _actor_response(actor)


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None
