"""JSON API routes for machine credential management."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.identity.machines import (
    create_machine_credential,
    regenerate_machine_client_secret,
    revoke_machine_credential,
)
from dionysus.models.identity import MachineCredential

router = APIRouter(prefix="/api/admin/machine-credentials", tags=["machine-credentials"])
credential_manage_actor_dependency = Depends(require_permission("credential:manage"))


class MachineCredentialCreateRequest(BaseModel):
    """Request body for creating a machine credential."""

    model_config = ConfigDict(extra="forbid")

    name: str


class MachineCredentialTokenActionRequest(BaseModel):
    """Request body for token-affecting credential actions."""

    model_config = ConfigDict(extra="forbid")

    revoke_tokens: bool = True


class MachineCredentialResponse(BaseModel):
    """Safe response body for a machine credential."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    client_id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None


class MachineCredentialWithSecretResponse(MachineCredentialResponse):
    """One-time response body for credential secret delivery."""

    client_secret: str


class MachineCredentialListResponse(BaseModel):
    """Response body for machine credential list queries."""

    model_config = ConfigDict(extra="forbid")

    credentials: list[MachineCredentialResponse]


@router.get("", response_model=MachineCredentialListResponse)
def machine_credentials_list_api(
    request: Request,
    _actor: AuthenticatedActor = credential_manage_actor_dependency,
) -> MachineCredentialListResponse:
    """Return machine credentials without raw or digested secret material.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.

    Returns:
        JSON-serializable machine credentials sorted by creation time.

    Raises:
        HTTPException: If authentication fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        credentials = session.scalars(
            select(MachineCredential).order_by(MachineCredential.created_at)
        ).all()
        return MachineCredentialListResponse(
            credentials=[_credential_response(credential) for credential in credentials]
        )


@router.post(
    "",
    response_model=MachineCredentialWithSecretResponse,
    status_code=status.HTTP_201_CREATED,
)
def machine_credential_create_api(
    request: Request,
    payload: MachineCredentialCreateRequest,
    actor: AuthenticatedActor = credential_manage_actor_dependency,
) -> MachineCredentialWithSecretResponse:
    """Create a machine credential and return its raw client secret once.

    Args:
        request: Incoming request containing application state.
        payload: Credential creation fields.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The created credential plus the one-time raw client secret.

    Raises:
        HTTPException: If authentication fails or the credential name already exists.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        try:
            raw_secret, credential = create_machine_credential(session, name=payload.name)
        except IntegrityError as exc:
            session.rollback()
            raise _duplicate_name_conflict() from exc
        record_audit_event(
            session,
            event_type="machine_credential.create",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="machine_credential",
            target_id=credential.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"name": credential.name},
        )
        session.commit()
        return _credential_with_secret_response(credential, raw_secret)


@router.post(
    "/{credential_id}/regenerate-secret",
    response_model=MachineCredentialWithSecretResponse,
)
def machine_credential_regenerate_secret_api(
    request: Request,
    credential_id: str,
    payload: MachineCredentialTokenActionRequest | None = None,
    actor: AuthenticatedActor = credential_manage_actor_dependency,
) -> MachineCredentialWithSecretResponse:
    """Regenerate a machine credential client secret.

    Args:
        request: Incoming request containing application state.
        credential_id: Machine credential UUID string.
        payload: Optional token revocation behavior.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The credential plus the one-time replacement raw client secret.

    Raises:
        HTTPException: If authentication fails or the credential is unknown.
    """

    revoke_tokens = True if payload is None else payload.revoke_tokens
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        credential = _get_credential_or_404(session, credential_id)
        raw_secret = regenerate_machine_client_secret(
            session,
            credential,
            now=datetime.now(UTC),
            revoke_tokens=revoke_tokens,
        )
        record_audit_event(
            session,
            event_type="machine_credential.regenerate_secret",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="machine_credential",
            target_id=credential.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"name": credential.name, "revoke_tokens": revoke_tokens},
        )
        session.commit()
        return _credential_with_secret_response(credential, raw_secret)


@router.post("/{credential_id}/revoke", response_model=MachineCredentialResponse)
def machine_credential_revoke_api(
    request: Request,
    credential_id: str,
    payload: MachineCredentialTokenActionRequest | None = None,
    actor: AuthenticatedActor = credential_manage_actor_dependency,
) -> MachineCredentialResponse:
    """Revoke a machine credential and optionally revoke its tokens.

    Args:
        request: Incoming request containing application state.
        credential_id: Machine credential UUID string.
        payload: Optional token revocation behavior.
        actor: Authorized browser or machine actor resolved by dependency.

    Returns:
        The revoked credential without raw or digested secret material.

    Raises:
        HTTPException: If authentication fails or the credential is unknown.
    """

    revoke_tokens = True if payload is None else payload.revoke_tokens
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        credential = _get_credential_or_404(session, credential_id)
        revoke_machine_credential(
            session,
            credential,
            now=datetime.now(UTC),
            revoke_tokens=revoke_tokens,
        )
        record_audit_event(
            session,
            event_type="machine_credential.revoke",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="machine_credential",
            target_id=credential.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"name": credential.name, "revoke_tokens": revoke_tokens},
        )
        session.commit()
        return _credential_response(credential)


def _credential_response(credential: MachineCredential) -> MachineCredentialResponse:
    return MachineCredentialResponse(
        id=credential.id,
        name=credential.name,
        client_id=credential.client_id,
        is_active=credential.is_active,
        created_at=_as_utc(credential.created_at),
        updated_at=_as_utc(credential.updated_at),
        revoked_at=_as_utc(credential.revoked_at) if credential.revoked_at else None,
    )


def _credential_with_secret_response(
    credential: MachineCredential,
    raw_secret: str,
) -> MachineCredentialWithSecretResponse:
    return MachineCredentialWithSecretResponse(
        **_credential_response(credential).model_dump(),
        client_secret=raw_secret,
    )


def _get_credential_or_404(session, credential_id: str) -> MachineCredential:
    credential = session.get(MachineCredential, credential_id)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Machine credential not found",
        )
    return credential


def _duplicate_name_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Machine credential name already exists",
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None
