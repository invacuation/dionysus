"""JSON API routes for admin user session management."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.identity.sessions import revoke_session
from dionysus.models.identity import UserSession

router = APIRouter(prefix="/api/admin/sessions", tags=["sessions"])
session_manage_actor_dependency = Depends(require_permission("session:manage"))


class UserSessionResponse(BaseModel):
    """Safe response body for a user session."""

    model_config = ConfigDict(extra="forbid")

    id: str
    user_id: str
    username: str
    display_name: str
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    active: bool


class UserSessionListResponse(BaseModel):
    """Response body for admin user session list queries."""

    model_config = ConfigDict(extra="forbid")

    sessions: list[UserSessionResponse]


@router.get("", response_model=UserSessionListResponse)
def user_sessions_list_api(
    request: Request,
    _actor: AuthenticatedActor = session_manage_actor_dependency,
) -> UserSessionListResponse:
    """Return user sessions without raw or digested token material.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.

    Returns:
        JSON-serializable user sessions sorted with newest sessions first.

    Raises:
        HTTPException: If authentication fails.
    """

    now = datetime.now(UTC)
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        session_records = session.scalars(
            select(UserSession)
            .options(selectinload(UserSession.user))
            .order_by(UserSession.created_at.desc())
        ).all()
        return UserSessionListResponse(
            sessions=[
                _session_response(session_record, now=now) for session_record in session_records
            ]
        )


@router.post("/{session_id}/revoke", response_model=UserSessionResponse)
def user_session_revoke_api(
    request: Request,
    session_id: str,
    actor: AuthenticatedActor = session_manage_actor_dependency,
) -> UserSessionResponse:
    """Revoke a user session and audit the revocation.

    Args:
        request: Incoming request containing application state and client
            metadata.
        session_id: User session UUID string.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The revoked session without raw or digested token material.

    Raises:
        HTTPException: If authentication fails or the session is unknown.
    """

    now = datetime.now(UTC)
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        session_record = _get_session_or_404(session, session_id)
        revoke_session(session, session_record, now=now)
        record_audit_event(
            session,
            event_type="auth.session.revoke",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="session",
            target_id=session_record.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "revoked_user_id": session_record.user_id,
                "revoked_username": session_record.user.username,
                "revoked_display_name": session_record.user.display_name,
            },
        )
        session.commit()
        return _session_response(session_record, now=now)


def _session_response(session_record: UserSession, *, now: datetime) -> UserSessionResponse:
    """Build a safe API response for a user session row."""

    return UserSessionResponse(
        id=session_record.id,
        user_id=session_record.user_id,
        username=session_record.user.username,
        display_name=session_record.user.display_name,
        ip_address=session_record.ip_address,
        user_agent=session_record.user_agent,
        created_at=_as_utc(session_record.created_at),
        last_seen_at=_as_utc(session_record.last_seen_at),
        idle_expires_at=_as_utc(session_record.idle_expires_at),
        expires_at=_as_utc(session_record.expires_at),
        revoked_at=_as_utc(session_record.revoked_at) if session_record.revoked_at else None,
        active=_is_active(session_record, now=now),
    )


def _get_session_or_404(session: Session, session_id: str) -> UserSession:
    """Return a user session row or raise a safe 404."""

    session_record = session.scalar(
        select(UserSession)
        .options(selectinload(UserSession.user))
        .where(UserSession.id == session_id)
    )
    if session_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )
    return session_record


def _is_active(session_record: UserSession, *, now: datetime) -> bool:
    """Return whether a session can still authenticate requests."""

    now = _as_utc(now)
    return (
        session_record.revoked_at is None
        and _as_utc(session_record.idle_expires_at) > now
        and _as_utc(session_record.expires_at) > now
    )


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, treating naive persisted values as UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _client_host(request: Request) -> str | None:
    """Return the client host when FastAPI has connection metadata."""

    return request.client.host if request.client else None
