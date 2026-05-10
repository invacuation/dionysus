"""Services for application security settings."""

from sqlalchemy.orm import Session

from dionysus.models.findings import RawFindingInstance
from dionysus.models.inventory import Project
from dionysus.models.settings import AppSecuritySettings

SETTINGS_SINGLETON_ID = "default"


def get_security_settings(session: Session) -> AppSecuritySettings:
    """Return the singleton security settings row, creating it when absent.

    Args:
        session: SQLAlchemy session used for lookup and persistence.

    Returns:
        The durable application security settings row.
    """

    settings = session.get(AppSecuritySettings, SETTINGS_SINGLETON_ID)
    if settings is not None:
        return settings

    settings = AppSecuritySettings(id=SETTINGS_SINGLETON_ID)
    session.add(settings)
    session.flush()
    return settings


def effective_session_timeout_minutes(
    session: Session,
    *,
    default_idle_timeout_minutes: int,
    default_absolute_timeout_minutes: int,
) -> tuple[int, int]:
    """Return effective browser session timeout settings.

    Args:
        session: SQLAlchemy session used for settings lookup.
        default_idle_timeout_minutes: Environment-backed idle timeout fallback.
        default_absolute_timeout_minutes: Environment-backed absolute timeout
            fallback.

    Returns:
        The effective idle and absolute timeout values in minutes.
    """

    settings = get_security_settings(session)
    return _effective_session_timeout_values(
        settings,
        default_idle_timeout_minutes=default_idle_timeout_minutes,
        default_absolute_timeout_minutes=default_absolute_timeout_minutes,
    )


def _effective_session_timeout_values(
    settings: AppSecuritySettings,
    *,
    default_idle_timeout_minutes: int,
    default_absolute_timeout_minutes: int,
) -> tuple[int, int]:
    """Resolve nullable durable timeout settings against defaults."""

    idle_timeout_minutes = (
        settings.session_idle_timeout_minutes
        if settings.session_idle_timeout_minutes is not None
        else default_idle_timeout_minutes
    )
    absolute_timeout_minutes = (
        settings.session_absolute_timeout_minutes
        if settings.session_absolute_timeout_minutes is not None
        else default_absolute_timeout_minutes
    )
    return idle_timeout_minutes, absolute_timeout_minutes


def effective_peer_review_required(
    session: Session,
    *,
    finding: RawFindingInstance,
    requested_peer_review: bool,
) -> bool:
    """Return whether a finding status transition requires peer review.

    Args:
        session: SQLAlchemy session used for settings lookup.
        finding: Finding whose project policy participates in the decision.
        requested_peer_review: Caller-requested review flag from the API.

    Returns:
        ``True`` when global policy, project policy, or the explicit request
        flag requires peer review.
    """

    if requested_peer_review:
        return True

    settings = get_security_settings(session)
    if settings.force_peer_review_for_status_changes:
        return True

    project = finding.project
    if project is None:
        project = session.get(Project, finding.project_id)
    return bool(project and project.require_peer_review_for_status_changes)


def update_security_settings(
    session: Session,
    *,
    force_peer_review_for_status_changes: bool,
    session_idle_timeout_minutes: int,
    session_absolute_timeout_minutes: int,
    default_idle_timeout_minutes: int,
    default_absolute_timeout_minutes: int,
) -> tuple[AppSecuritySettings, dict[str, dict[str, bool | int]]]:
    """Update application security settings and return meaningful changes.

    Args:
        session: SQLAlchemy session used for lookup and persistence.
        force_peer_review_for_status_changes: New global peer-review setting.
        session_idle_timeout_minutes: New browser session idle timeout in
            minutes.
        session_absolute_timeout_minutes: New browser session absolute timeout
            in minutes.
        default_idle_timeout_minutes: Environment-backed idle timeout fallback
            used for change reporting when no durable value exists.
        default_absolute_timeout_minutes: Environment-backed absolute timeout
            fallback used for change reporting when no durable value exists.

    Returns:
        The settings row and a mapping of changed field names to old/new values.
    """

    settings = get_security_settings(session)
    changes: dict[str, dict[str, bool | int]] = {}
    if settings.force_peer_review_for_status_changes != force_peer_review_for_status_changes:
        changes["force_peer_review_for_status_changes"] = {
            "old": settings.force_peer_review_for_status_changes,
            "new": force_peer_review_for_status_changes,
        }
        settings.force_peer_review_for_status_changes = force_peer_review_for_status_changes

    current_idle_timeout, current_absolute_timeout = _effective_session_timeout_values(
        settings,
        default_idle_timeout_minutes=default_idle_timeout_minutes,
        default_absolute_timeout_minutes=default_absolute_timeout_minutes,
    )
    if current_idle_timeout != session_idle_timeout_minutes:
        changes["session_idle_timeout_minutes"] = {
            "old": current_idle_timeout,
            "new": session_idle_timeout_minutes,
        }
        settings.session_idle_timeout_minutes = session_idle_timeout_minutes
    if current_absolute_timeout != session_absolute_timeout_minutes:
        changes["session_absolute_timeout_minutes"] = {
            "old": current_absolute_timeout,
            "new": session_absolute_timeout_minutes,
        }
        settings.session_absolute_timeout_minutes = session_absolute_timeout_minutes
    return settings, changes
