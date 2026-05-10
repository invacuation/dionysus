"""Machine OAuth-style token API routes."""

from datetime import UTC, datetime
from json import JSONDecodeError
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, ValidationError

from dionysus.identity.machines import exchange_machine_client_secret

router = APIRouter(prefix="/api/oauth", tags=["oauth"])

CLIENT_CREDENTIALS_GRANT = "client_credentials"
BEARER_AUTH_SCHEME = "bearer"


class TokenRequest(BaseModel):
    """Machine token exchange request body."""

    model_config = ConfigDict(extra="forbid")

    grant_type: str
    client_id: str
    client_secret: str


class TokenResponse(BaseModel):
    """Machine bearer and refresh token response body."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int


def _invalid_client_credentials() -> HTTPException:
    """Return the generic machine credential exchange failure.

    Returns:
        A 401 HTTP exception that does not reveal whether the client ID or
        client secret failed verification.
    """

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid client credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _invalid_token_request() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Invalid token request",
    )


async def _token_request_from_request(request: Request) -> TokenRequest:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    try:
        payload: Any
        if content_type in {
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        }:
            payload = dict(await request.form())
        else:
            payload = await request.json()
        return TokenRequest.model_validate(payload)
    except (JSONDecodeError, ValidationError):
        raise _invalid_token_request() from None


@router.post("/token", response_model=TokenResponse)
async def create_machine_token(request: Request, response: Response) -> TokenResponse:
    """Exchange machine client credentials for bearer tokens.

    Args:
        request: Incoming request containing application state.
        response: Outgoing response whose headers are updated for successful
            token exchanges.

    Returns:
        An OAuth2-ish bearer access token response with a rotating refresh
        token.

    Raises:
        HTTPException: If the grant type is unsupported or credentials fail
            generic verification.
    """

    credentials = await _token_request_from_request(request)
    if credentials.grant_type != CLIENT_CREDENTIALS_GRANT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant_type",
        )

    session_factory = request.app.state.session_factory
    settings = request.app.state.settings
    access_expires_minutes = settings.machine_access_token_expires_minutes
    refresh_expires_minutes = settings.machine_refresh_token_expires_minutes

    with session_factory() as db_session:
        token_pair = exchange_machine_client_secret(
            db_session,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            now=datetime.now(UTC),
            access_expires_in_minutes=access_expires_minutes,
            refresh_expires_in_minutes=refresh_expires_minutes,
        )
        if token_pair is None:
            raise _invalid_client_credentials()
        db_session.commit()

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return TokenResponse(
        access_token=token_pair.access_token,
        token_type=BEARER_AUTH_SCHEME,
        expires_in=access_expires_minutes * 60,
        refresh_token=token_pair.refresh_token,
        refresh_expires_in=refresh_expires_minutes * 60,
    )
