"""Estate overview query helpers."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dionysus.findings.sla import calculate_sla_state
from dionysus.models.findings import FindingStatus, RawFindingInstance
from dionysus.models.inventory import Project


@dataclass(frozen=True)
class SeverityCount:
    """Finding count for one severity.

    Attributes:
        severity: Scanner severity label.
        count: Number of open findings with this severity.
    """

    severity: str
    count: int


@dataclass(frozen=True)
class ProjectRiskSummary:
    """Open finding summary for one project.

    Attributes:
        project_id: Opaque project identifier for scoped navigation.
        project_name: Human-readable project name.
        open_count: Number of open findings in the project.
        overdue_count: Number of open findings with breached SLA.
    """

    project_id: str
    project_name: str
    open_count: int
    overdue_count: int


@dataclass(frozen=True)
class EstateOverview:
    """Aggregate vulnerability posture for the Overview page.

    Attributes:
        open_findings: Total open finding count.
        overdue_sla: Count of open findings with breached primary SLA.
        grace_period_risk: Count of open findings with breached grace SLA.
        severity_counts: Open findings grouped by severity.
        highest_risk_projects: Projects ordered by open and overdue finding counts.
    """

    open_findings: int
    overdue_sla: int
    grace_period_risk: int
    severity_counts: list[SeverityCount]
    highest_risk_projects: list[ProjectRiskSummary]


def get_estate_overview(session: Session, *, now: datetime | None = None) -> EstateOverview:
    """Return aggregate finding posture for the whole estate.

    Args:
        session: Database session used for overview queries.
        now: Optional current time for SLA calculations.

    Returns:
        Estate overview counts for dashboard rendering.
    """

    current_time = now or datetime.now(UTC)
    open_findings = list(
        session.scalars(
            select(RawFindingInstance).where(RawFindingInstance.status == FindingStatus.OPEN)
        )
    )
    projects = {
        project.id: project
        for project in session.scalars(select(Project).order_by(Project.name, Project.slug))
    }

    severity_rows = session.execute(
        select(RawFindingInstance.severity, func.count())
        .where(RawFindingInstance.status == FindingStatus.OPEN)
        .group_by(RawFindingInstance.severity)
        .order_by(RawFindingInstance.severity)
    )
    severity_counts = [
        SeverityCount(severity=str(severity).title(), count=int(count))
        for severity, count in severity_rows
    ]

    overdue_sla = 0
    grace_period_risk = 0
    project_counts: dict[str, ProjectRiskSummary] = {}
    for finding in open_findings:
        project = projects.get(finding.project_id)
        if project is None:
            continue
        sla_state = calculate_sla_state(
            project,
            finding.scan_target,
            finding,
            now=current_time,
        )
        include_in_sla_reports = sla_state.include_in_sla_reports
        is_overdue = (
            include_in_sla_reports
            and sla_state.remaining_days is not None
            and sla_state.remaining_days < 0
        )
        is_grace_overdue = (
            include_in_sla_reports
            and sla_state.grace_remaining_days is not None
            and sla_state.grace_remaining_days < 0
        )
        if is_overdue:
            overdue_sla += 1
        if is_grace_overdue:
            grace_period_risk += 1
        current = project_counts.get(
            project.id,
            ProjectRiskSummary(
                project_id=project.id,
                project_name=project.name,
                open_count=0,
                overdue_count=0,
            ),
        )
        project_counts[project.id] = ProjectRiskSummary(
            project_id=project.id,
            project_name=project.name,
            open_count=current.open_count + 1,
            overdue_count=current.overdue_count + int(is_overdue),
        )

    highest_risk_projects = sorted(
        project_counts.values(),
        key=lambda item: (item.overdue_count, item.open_count, item.project_name.casefold()),
        reverse=True,
    )[:5]

    return EstateOverview(
        open_findings=len(open_findings),
        overdue_sla=overdue_sla,
        grace_period_risk=grace_period_risk,
        severity_counts=severity_counts,
        highest_risk_projects=highest_risk_projects,
    )
