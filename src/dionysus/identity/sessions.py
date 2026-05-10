"""User session creation, lookup, expiry touch, and revocation services."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.models.identity import User, UserSession
from dionysus.security.tokens import generate_token, token_digest


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, treating naive persisted values as UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def create_session(
    session: Session,
    *,
    user: User,
    now: datetime,
    idle_timeout_minutes: int,
    absolute_timeout_minutes: int,
    user_agent: str | None,
    ip_address: str | None,
) -> tuple[str, UserSession]:
    """Create a user session and return the raw token once.

    Only the token digest is stored, so callers must hand the raw token to the
    client immediately and cannot recover it from the database later.

    Args:
        session: The database session used to persist the session record.
        user: The user that owns the new session.
        now: The current time used to calculate session expiry.
        idle_timeout_minutes: Minutes of inactivity allowed before expiry.
        absolute_timeout_minutes: Maximum lifetime in minutes before expiry.
        user_agent: Optional user agent metadata to store with the session.
        ip_address: Optional IP address metadata to store with the session.

    Returns:
        A tuple of the raw bearer token and the flushed session record.
    """

    now = _as_utc(now)
    raw_token = generate_token()
    session_record = UserSession(
        user=user,
        token_digest=token_digest(raw_token),
        user_agent=user_agent,
        ip_address=ip_address,
        expires_at=now + timedelta(minutes=absolute_timeout_minutes),
        idle_expires_at=now + timedelta(minutes=idle_timeout_minutes),
        last_seen_at=now,
    )
    session.add(session_record)
    session.flush()
    return raw_token, session_record


def get_active_session(
    session: Session,
    raw_token: str,
    *,
    now: datetime,
    idle_timeout_minutes: int,
) -> UserSession | None:
    """Return and touch an active session for a raw token.

    The raw token is digested for lookup; only active, unexpired, unrevoked
    session records are returned.

    Args:
        session: The database session used for lookup and touch updates.
        raw_token: The bearer token supplied by the client.
        now: The current time used for expiry checks.
        idle_timeout_minutes: Minutes to extend the idle expiry, capped by the
            absolute expiry.

    Returns:
        The touched active session, or ``None`` when the token is unknown,
        revoked, idle-expired, or absolute-expired.
    """

    now = _as_utc(now)
    session_record = session.scalar(
        select(UserSession).where(UserSession.token_digest == token_digest(raw_token))
    )
    if session_record is None or session_record.revoked_at is not None:
        return None
    expires_at = _as_utc(session_record.expires_at)
    idle_expires_at = _as_utc(session_record.idle_expires_at)
    if expires_at <= now or idle_expires_at <= now:
        return None
    session_record.expires_at = expires_at
    session_record.last_seen_at = now
    session_record.idle_expires_at = min(
        now + timedelta(minutes=idle_timeout_minutes),
        expires_at,
    )
    session.flush()
    return session_record


def revoke_session(session: Session, session_record: UserSession, *, now: datetime) -> None:
    """Mark a session as revoked so future token lookups are rejected.

    Args:
        session: The database session used to flush the revocation timestamp.
        session_record: The session record to revoke.
        now: The revocation time to store.

    Returns:
        None.
    """

    session_record.revoked_at = _as_utc(now)
    session.flush()
