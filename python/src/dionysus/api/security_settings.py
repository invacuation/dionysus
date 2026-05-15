"""JSON API routes for application security settings."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor
from dionysus.identity.authorization import require_permission
from dionysus.security.settings import (
    effective_session_timeout_minutes,
    get_security_settings,
    update_security_settings,
)

router = APIRouter(prefix="/api/admin/security-settings", tags=["security-settings"])
security_settings_manage_actor_dependency = Depends(require_permission("security_settings:manage"))


class SecuritySettingsResponse(BaseModel):
    """Safe application security settings response body.

    Attributes:
        force_peer_review_for_status_changes: Whether finding status changes
            are globally forced through peer review.
    """

    model_config = ConfigDict(extra="forbid")

    force_peer_review_for_status_changes: bool
    session_idle_timeout_minutes: int
    session_absolute_timeout_minutes: int


class SecuritySettingsUpdateRequest(BaseModel):
    """Request body for updating application security settings.

    Attributes:
        force_peer_review_for_status_changes: New global peer-review setting.
    """

    model_config = ConfigDict(extra="forbid")

    force_peer_review_for_status_changes: bool
    session_idle_timeout_minutes: int = Field(ge=1)
    session_absolute_timeout_minutes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_timeout_order(self) -> "SecuritySettingsUpdateRequest":
        """Require absolute browser session timeout to cover idle timeout."""

        if self.session_absolute_timeout_minutes < self.session_idle_timeout_minutes:
            raise ValueError(
                "session_absolute_timeout_minutes must be greater than or equal to "
                "session_idle_timeout_minutes"
            )
        return self


@router.get("", response_model=SecuritySettingsResponse)
def security_settings_get_api(
    request: Request,
    _actor: AuthenticatedActor = security_settings_manage_actor_dependency,
) -> SecuritySettingsResponse:
    """Return application security settings.

    Args:
        request: Incoming request containing application state.
        _actor: Authorized request actor required for access.

    Returns:
        JSON-serializable security settings.
    """

    session_factory = request.app.state.session_factory
    app_settings = request.app.state.settings
    with session_factory() as session:
        settings = get_security_settings(session)
        idle_timeout_minutes, absolute_timeout_minutes = effective_session_timeout_minutes(
            session,
            default_idle_timeout_minutes=app_settings.session_idle_timeout_minutes,
            default_absolute_timeout_minutes=app_settings.session_absolute_timeout_minutes,
        )
        session.commit()
        return _settings_response(
            settings.force_peer_review_for_status_changes,
            session_idle_timeout_minutes=idle_timeout_minutes,
            session_absolute_timeout_minutes=absolute_timeout_minutes,
        )


@router.patch("", response_model=SecuritySettingsResponse)
def security_settings_update_api(
    request: Request,
    payload: SecuritySettingsUpdateRequest,
    actor: AuthenticatedActor = security_settings_manage_actor_dependency,
) -> SecuritySettingsResponse:
    """Update application security settings.

    Args:
        request: Incoming request containing application state.
        payload: Security settings fields supplied as JSON.
        actor: Authorized request actor required for access.

    Returns:
        JSON-serializable updated security settings.
    """

    session_factory = request.app.state.session_factory
    app_settings = request.app.state.settings
    with session_factory() as session:
        settings, changes = update_security_settings(
            session,
            force_peer_review_for_status_changes=payload.force_peer_review_for_status_changes,
            session_idle_timeout_minutes=payload.session_idle_timeout_minutes,
            session_absolute_timeout_minutes=payload.session_absolute_timeout_minutes,
            default_idle_timeout_minutes=app_settings.session_idle_timeout_minutes,
            default_absolute_timeout_minutes=app_settings.session_absolute_timeout_minutes,
        )
        if changes:
            record_audit_event(
                session,
                event_type="security.settings.update",
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                actor_display=actor.display_name,
                target_type="app_security_settings",
                target_id=settings.id,
                ip_address=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "changed_fields": list(changes),
                    "changes": changes,
                },
            )
        session.commit()
        return _settings_response(
            settings.force_peer_review_for_status_changes,
            session_idle_timeout_minutes=payload.session_idle_timeout_minutes,
            session_absolute_timeout_minutes=payload.session_absolute_timeout_minutes,
        )


def _settings_response(
    force_peer_review_for_status_changes: bool,
    *,
    session_idle_timeout_minutes: int,
    session_absolute_timeout_minutes: int,
) -> SecuritySettingsResponse:
    """Build a safe API response for security settings.

    Args:
        force_peer_review_for_status_changes: Global peer-review setting.
        session_idle_timeout_minutes: Effective browser session idle timeout.
        session_absolute_timeout_minutes: Effective browser session absolute
            timeout.

    Returns:
        JSON-serializable security settings response.
    """

    return SecuritySettingsResponse(
        force_peer_review_for_status_changes=force_peer_review_for_status_changes,
        session_idle_timeout_minutes=session_idle_timeout_minutes,
        session_absolute_timeout_minutes=session_absolute_timeout_minutes,
    )


def _client_host(request: Request) -> str | None:
    """Return the request client host for audit logging.

    Args:
        request: Incoming request with optional client connection metadata.

    Returns:
        The client host string, or ``None`` when unavailable.
    """

    return request.client.host if request.client else None
