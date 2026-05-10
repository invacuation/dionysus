"""SLA calculations for persisted findings."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from dionysus.models.findings import FindingStatus, RawFindingInstance
from dionysus.models.inventory import AssetNode, Project


@dataclass(frozen=True)
class SlaState:
    """Calculated SLA state for a finding.

    Attributes:
        active: Whether the SLA clock is running for the finding.
        remaining_days: Whole days remaining before the primary SLA is due.
        grace_remaining_days: Whole days remaining before the grace period is due.
        include_in_sla_reports: Whether reporting queries should include this finding.
        status: Machine-readable SLA status.
        reason: Human-readable reason for inactive or excluded states.
        sla_days: Configured primary SLA length in days.
        grace_days: Configured grace-period length in days.
    """

    active: bool
    remaining_days: int | None
    grace_remaining_days: int | None
    include_in_sla_reports: bool
    status: str
    reason: str | None = None
    sla_days: int | None = None
    grace_days: int | None = None


def calculate_sla_state(
    project: Project,
    asset: AssetNode | None,
    finding: RawFindingInstance,
    *,
    now: datetime,
) -> SlaState:
    """Calculate the SLA clock state for a persisted finding.

    Args:
        project: Project that owns the finding and default SLA settings.
        asset: Optional asset node whose SLA overrides may apply.
        finding: Raw finding instance to evaluate.
        now: Time used as the reference point for remaining-day calculations.

    Returns:
        Calculated SLA state, including reporting inclusion.
    """

    include_in_reports = _reporting_enabled(project, asset)
    if finding.status != FindingStatus.OPEN:
        return SlaState(
            active=False,
            remaining_days=None,
            grace_remaining_days=None,
            include_in_sla_reports=False,
            status="not_applicable",
            reason="finding_not_open",
        )

    if not _tracking_enabled(project, asset):
        return SlaState(
            active=False,
            remaining_days=None,
            grace_remaining_days=None,
            include_in_sla_reports=include_in_reports,
            status="tracking_disabled",
            reason="sla_tracking_disabled",
        )

    now = _as_utc(now)
    first_seen_at = _as_utc(finding.first_seen_at)
    sla_days = max(0, _sla_days_for_severity(project, finding.severity))
    due_at = first_seen_at + timedelta(days=sla_days)
    remaining_days = (due_at - now).days
    grace_days = _grace_days(project, sla_days)
    grace_remaining_days = remaining_days + grace_days if grace_days is not None else None

    return SlaState(
        active=True,
        remaining_days=remaining_days,
        grace_remaining_days=grace_remaining_days,
        include_in_sla_reports=include_in_reports,
        status="active",
        sla_days=sla_days,
        grace_days=grace_days,
    )


def _tracking_enabled(project: Project, asset: AssetNode | None) -> bool:
    if project.sla_tracking_enabled is False:
        return False
    if asset is not None and asset.sla_tracking_enabled is not None:
        return asset.sla_tracking_enabled
    return True


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, treating naive persisted values as UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _reporting_enabled(project: Project, asset: AssetNode | None) -> bool:
    if project.sla_reporting_enabled is False:
        return False
    if asset is not None and asset.sla_reporting_enabled is not None:
        return asset.sla_reporting_enabled
    return True


def _sla_days_for_severity(project: Project, severity: str) -> int:
    field_name = {
        "critical": "critical_sla_days",
        "high": "high_sla_days",
        "medium": "medium_sla_days",
        "low": "low_sla_days",
        "unknown": "unknown_sla_days",
    }.get(severity.casefold(), "unknown_sla_days")
    configured_days = getattr(project, field_name)
    default_days = {
        "critical_sla_days": 30,
        "high_sla_days": 60,
        "medium_sla_days": 90,
        "low_sla_days": 180,
        "unknown_sla_days": 365,
    }[field_name]
    return default_days if configured_days is None else configured_days


def _grace_days(project: Project, sla_days: int) -> int | None:
    if project.grace_period_enabled is not True:
        return None
    grace_period_percent = (
        100 if project.grace_period_percent is None else project.grace_period_percent
    )
    return max(0, sla_days * grace_period_percent // 100)
