"""JSON API routes for estate overview data."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from dionysus.identity.actors import AuthenticatedActor, get_authenticated_actor
from dionysus.identity.authorization import ensure_actor_permission
from dionysus.overview import get_estate_overview

router = APIRouter(prefix="/api", tags=["overview"])
authenticated_actor_dependency = Depends(get_authenticated_actor)


class SeverityCount(BaseModel):
    """Open finding count for one scanner severity."""

    model_config = ConfigDict(extra="forbid")

    severity: str
    count: int


class ProjectRiskSummary(BaseModel):
    """Open finding and SLA risk summary for one project."""

    model_config = ConfigDict(extra="forbid")

    project_id: str
    project_name: str
    open_count: int
    overdue_count: int


class OverviewResponse(BaseModel):
    """Response body for estate overview metrics."""

    model_config = ConfigDict(extra="forbid")

    open_findings: int
    overdue_sla: int
    grace_period_risk: int
    severity_counts: list[SeverityCount]
    highest_risk_projects: list[ProjectRiskSummary]


@router.get("/overview", response_model=OverviewResponse)
def overview_api(
    request: Request,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> OverviewResponse:
    """Return estate overview metrics for the React frontend.

    Args:
        request: Incoming request containing application state.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable overview metrics.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        ensure_actor_permission(
            session,
            actor=actor,
            permission="report:view",
            scope_type=None,
            scope_id=None,
        )
        overview = get_estate_overview(session, now=datetime.now(UTC))
        return OverviewResponse(
            open_findings=overview.open_findings,
            overdue_sla=overview.overdue_sla,
            grace_period_risk=overview.grace_period_risk,
            severity_counts=[
                SeverityCount(severity=row.severity, count=row.count)
                for row in overview.severity_counts
            ],
            highest_risk_projects=[
                ProjectRiskSummary(
                    project_id=row.project_id,
                    project_name=row.project_name,
                    open_count=row.open_count,
                    overdue_count=row.overdue_count,
                )
                for row in overview.highest_risk_projects
            ],
        )
