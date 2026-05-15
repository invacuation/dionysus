"""Machine credential and bearer token services."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hmac import compare_digest

from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.models.identity import MachineCredential, MachineRefreshToken, MachineToken
from dionysus.security.tokens import generate_token, token_digest


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, treating naive persisted values as UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True)
class MachineTokenPair:
    """Raw and persisted tokens returned from machine-token exchanges.

    Access tokens are short-lived bearer credentials. Refresh tokens are
    longer-lived bearer credentials that must be stored only by the client and
    are rotated on every refresh exchange.
    """

    access_token: str
    refresh_token: str
    access_token_record: MachineToken
    refresh_token_record: MachineRefreshToken


def create_machine_credential(session: Session, *, name: str) -> tuple[str, MachineCredential]:
    """Create a machine credential and return the raw client secret once.

    The raw secret is generated for immediate client delivery and only its
    digest is stored. Callers cannot recover the raw secret from the database.

    Args:
        session: The database session used to persist the credential.
        name: The unique human-readable machine credential name.

    Returns:
        A tuple of the raw client secret and the flushed credential record.
    """

    raw_secret = generate_token()
    credential = MachineCredential(name=name, client_secret_digest=token_digest(raw_secret))
    session.add(credential)
    session.flush()
    return raw_secret, credential


def regenerate_machine_client_secret(
    session: Session,
    credential: MachineCredential,
    *,
    now: datetime,
    revoke_tokens: bool = True,
) -> str:
    """Regenerate a machine client secret and return the raw secret once.

    Security note: the previous client secret stops matching immediately
    because only the new secret digest is stored. When ``revoke_tokens`` is
    enabled, all currently unrevoked access-token and refresh-token rows for
    this credential are stamped with the same UTC revocation time. When it is
    disabled, existing token rows remain usable until their normal expiry or
    explicit revocation, including refresh-token rotation.

    Args:
        session: The database session used for credential and token updates.
        credential: The machine credential whose client secret is regenerated.
        now: The revocation time to store when token revocation is enabled,
            normalized to UTC.
        revoke_tokens: Whether to mark unrevoked access and refresh tokens for
            this credential as revoked.

    Returns:
        The new raw client secret, which is not recoverable after this return.
    """

    now = _as_utc(now)
    raw_secret = generate_token()
    credential.client_secret_digest = token_digest(raw_secret)
    if revoke_tokens:
        session.flush()
        session.query(MachineToken).filter(
            MachineToken.machine_credential_id == credential.id,
            MachineToken.revoked_at.is_(None),
        ).update(
            {MachineToken.revoked_at: now},
            synchronize_session="evaluate",
        )
        session.query(MachineRefreshToken).filter(
            MachineRefreshToken.machine_credential_id == credential.id,
            MachineRefreshToken.revoked_at.is_(None),
        ).update(
            {MachineRefreshToken.revoked_at: now},
            synchronize_session="evaluate",
        )
        for instance in session.identity_map.values():
            if (
                isinstance(instance, MachineToken | MachineRefreshToken)
                and instance.machine_credential_id == credential.id
                and instance.revoked_at is None
            ):
                instance.revoked_at = now
    session.flush()
    return raw_secret


def verify_machine_client_secret(credential: MachineCredential, raw_secret: str) -> bool:
    """Return whether a raw client secret matches an active credential.

    The raw secret is digested before comparison and checked with constant-time
    comparison. Revoked or inactive credentials fail closed.

    Args:
        credential: The machine credential record to verify.
        raw_secret: The raw client secret supplied by the client.

    Returns:
        ``True`` when the secret matches an active credential; otherwise ``False``.
    """

    if not credential.is_active or credential.revoked_at is not None:
        return False
    return compare_digest(credential.client_secret_digest, token_digest(raw_secret))


def revoke_machine_access_token(session: Session, token: MachineToken, *, now: datetime) -> None:
    """Mark a machine access token as revoked.

    Security note: revocation uses the persisted token row and never requires
    the raw bearer token, so callers can invalidate access without handling
    token material. Future access-token verification rejects revoked rows.

    Args:
        session: The database session used to flush the revocation timestamp.
        token: The machine access-token record to revoke.
        now: The revocation time to store, normalized to UTC.

    Returns:
        None.
    """

    token.revoked_at = _as_utc(now)
    session.flush()


def revoke_machine_refresh_token(
    session: Session,
    token: MachineRefreshToken,
    *,
    now: datetime,
) -> None:
    """Mark a machine refresh token as revoked.

    Security note: refresh tokens are bearer credentials and should be treated
    as single-use or explicitly revoked. Future refresh exchanges reject rows
    with a revocation timestamp.

    Args:
        session: The database session used to flush the revocation timestamp.
        token: The machine refresh-token record to revoke.
        now: The revocation time to store, normalized to UTC.

    Returns:
        None.
    """

    token.revoked_at = _as_utc(now)
    session.flush()


def revoke_machine_credential(
    session: Session,
    credential: MachineCredential,
    *,
    now: datetime,
    revoke_tokens: bool = True,
) -> None:
    """Revoke a machine credential and optionally revoke its token rows.

    Security note: disabling the credential prevents client-secret exchange,
    access-token verification, and refresh-token rotation even when existing
    token rows are left unrevoked for audit distinction. Setting
    ``revoke_tokens`` additionally stamps all currently unrevoked token rows
    for the credential with the same revocation time.

    Args:
        session: The database session used for credential and token updates.
        credential: The machine credential record to revoke.
        now: The revocation time to store, normalized to UTC.
        revoke_tokens: Whether to mark unrevoked access and refresh tokens for
            this credential as revoked.

    Returns:
        None.
    """

    now = _as_utc(now)
    credential.revoked_at = now
    credential.is_active = False
    if revoke_tokens:
        session.flush()
        session.query(MachineToken).filter(
            MachineToken.machine_credential_id == credential.id,
            MachineToken.revoked_at.is_(None),
        ).update(
            {MachineToken.revoked_at: now},
            synchronize_session="evaluate",
        )
        session.query(MachineRefreshToken).filter(
            MachineRefreshToken.machine_credential_id == credential.id,
            MachineRefreshToken.revoked_at.is_(None),
        ).update(
            {MachineRefreshToken.revoked_at: now},
            synchronize_session="evaluate",
        )
        for instance in session.identity_map.values():
            if (
                isinstance(instance, MachineToken | MachineRefreshToken)
                and instance.machine_credential_id == credential.id
                and instance.revoked_at is None
            ):
                instance.revoked_at = now
    session.flush()


def _issue_machine_access_token(
    session: Session,
    *,
    credential: MachineCredential,
    now: datetime,
    expires_in_minutes: int,
) -> tuple[str, MachineToken]:
    """Issue a machine bearer access token and return the raw token once.

    Only the token digest is stored, so callers must hand the raw bearer token
    to the client immediately and cannot recover it later.

    Args:
        session: The database session used to persist the token record.
        credential: The machine credential that owns the issued token.
        now: The current time used to calculate token expiry.
        expires_in_minutes: Number of minutes before the token expires.

    Returns:
        A tuple of the raw bearer token and the flushed token record.
    """

    now = _as_utc(now)
    raw_token = generate_token()
    token = MachineToken(
        machine_credential_id=credential.id,
        token_digest=token_digest(raw_token),
        expires_at=now + timedelta(minutes=expires_in_minutes),
    )
    session.add(token)
    session.flush()
    return raw_token, token


def _mint_machine_refresh_token(
    session: Session,
    credential: MachineCredential,
    now: datetime,
    expires_in_minutes: int,
) -> tuple[str, MachineRefreshToken]:
    """Issue a rotating machine refresh token and return the raw token once.

    Security note: only the refresh token digest is stored. Callers must hand
    the raw token to the client immediately, and later exchanges revoke the
    used refresh-token record before issuing a replacement.

    Args:
        session: The database session used to persist the refresh token record.
        credential: The machine credential that owns the issued refresh token.
        now: The current time used to calculate refresh-token expiry.
        expires_in_minutes: Number of minutes before the refresh token expires.

    Returns:
        A tuple of the raw refresh token and the flushed refresh token record.
    """

    now = _as_utc(now)
    raw_token = generate_token()
    refresh_token = MachineRefreshToken(
        machine_credential_id=credential.id,
        token_digest=token_digest(raw_token),
        expires_at=now + timedelta(minutes=expires_in_minutes),
    )
    session.add(refresh_token)
    session.flush()
    return raw_token, refresh_token


def exchange_machine_client_secret(
    session: Session,
    *,
    client_id: str,
    client_secret: str,
    now: datetime,
    access_expires_in_minutes: int,
    refresh_expires_in_minutes: int,
) -> MachineTokenPair | None:
    """Exchange machine client credentials for access and refresh tokens.

    Security note: this is a machine-to-machine credential exchange only. It
    does not implement browser OAuth, delegated authorization, redirect URIs,
    scopes consent, or authorization-code flow.

    Args:
        session: The database session used for credential lookup and token
            persistence.
        client_id: The long-lived machine client identifier.
        client_secret: The long-lived machine client secret supplied by the
            client.
        now: The current time used to calculate token expiry.
        access_expires_in_minutes: Number of minutes before the access token
            expires.
        refresh_expires_in_minutes: Number of minutes before the refresh token
            expires.

    Returns:
        A token pair for a valid active credential, or ``None`` when exchange
        fails.
    """

    now = _as_utc(now)
    credential = session.scalar(
        select(MachineCredential).where(MachineCredential.client_id == client_id)
    )
    if credential is None or not verify_machine_client_secret(credential, client_secret):
        return None

    access_token, access_token_record = _issue_machine_access_token(
        session,
        credential=credential,
        now=now,
        expires_in_minutes=access_expires_in_minutes,
    )
    refresh_token, refresh_token_record = _mint_machine_refresh_token(
        session,
        credential,
        now,
        refresh_expires_in_minutes,
    )
    return MachineTokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_record=access_token_record,
        refresh_token_record=refresh_token_record,
    )


def _credential_is_active(credential: MachineCredential | None) -> bool:
    """Return whether a machine credential can be used for token exchange."""

    return credential is not None and credential.is_active and credential.revoked_at is None


def verify_machine_access_token(
    session: Session,
    raw_token: str,
    *,
    now: datetime,
) -> MachineToken | None:
    """Return an active machine access token for a raw bearer token.

    The raw token is digested for lookup. Unknown, revoked, and expired tokens
    are rejected without exposing the stored digest. Tokens owned by inactive
    or revoked credentials are rejected so disabling a machine credential cuts
    off future access-token verification.

    Args:
        session: The database session used for lookup.
        raw_token: The bearer token supplied by the client.
        now: The current time used for expiry checks.

    Returns:
        The matching active token, or ``None`` when verification fails.
    """

    now = _as_utc(now)
    digest = token_digest(raw_token)
    token = session.scalar(select(MachineToken).where(MachineToken.token_digest == digest))
    if token is None or not compare_digest(token.token_digest, digest):
        return None
    credential = session.get(MachineCredential, token.machine_credential_id)
    if (
        not _credential_is_active(credential)
        or token.revoked_at is not None
        or _as_utc(token.expires_at) <= now
    ):
        return None
    token.expires_at = _as_utc(token.expires_at)
    return token


def refresh_machine_token(
    session: Session,
    raw_refresh_token: str,
    *,
    now: datetime,
    access_expires_in_minutes: int,
    refresh_expires_in_minutes: int,
) -> MachineTokenPair | None:
    """Rotate a machine refresh token and issue a new token pair.

    Security note: refresh tokens are single-use bearer credentials. A valid
    refresh exchange revokes the presented refresh token before issuing the new
    access token and replacement refresh token for the same machine credential.

    Args:
        session: The database session used for lookup, revocation, and token
            persistence.
        raw_refresh_token: The raw refresh token supplied by the client.
        now: The current time used for expiry checks and new token expiry.
        access_expires_in_minutes: Number of minutes before the new access
            token expires.
        refresh_expires_in_minutes: Number of minutes before the replacement
            refresh token expires.

    Returns:
        A rotated token pair, or ``None`` when the refresh token or owning
        credential is invalid.
    """

    now = _as_utc(now)
    digest = token_digest(raw_refresh_token)
    refresh_token_record = session.scalar(
        select(MachineRefreshToken).where(MachineRefreshToken.token_digest == digest)
    )
    if (
        refresh_token_record is None
        or not compare_digest(refresh_token_record.token_digest, digest)
        or refresh_token_record.revoked_at is not None
        or _as_utc(refresh_token_record.expires_at) <= now
    ):
        return None

    credential = session.get(MachineCredential, refresh_token_record.machine_credential_id)
    if credential is None or not _credential_is_active(credential):
        return None

    refresh_token_record.expires_at = _as_utc(refresh_token_record.expires_at)
    refresh_token_record.revoked_at = now
    access_token, access_token_record = _issue_machine_access_token(
        session,
        credential=credential,
        now=now,
        expires_in_minutes=access_expires_in_minutes,
    )
    refresh_token, new_refresh_token_record = _mint_machine_refresh_token(
        session,
        credential,
        now,
        refresh_expires_in_minutes,
    )
    session.flush()
    return MachineTokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_record=access_token_record,
        refresh_token_record=new_refresh_token_record,
    )
