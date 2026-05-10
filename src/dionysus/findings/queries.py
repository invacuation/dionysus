"""Reusable query services for finding browsing and detail views."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Select, and_, false, func, select
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

from dionysus.findings.sla import SlaState, calculate_sla_state
from dionysus.models.findings import (
    FindingComment,
    FindingStatus,
    FindingStatusChangeRequest,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

_SEVERITY_RANK = {
    "UNKNOWN": 0,
    "INFORMATIONAL": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}
_FindingJoinRow = tuple[
    RawFindingInstance,
    Project,
    AssetNode,
    ProjectVulnerabilityGroup,
]


class SortDirection(StrEnum):
    """Finding query sort directions."""

    ASC = "asc"
    DESC = "desc"


class SortKey(StrEnum):
    """Finding query sort keys."""

    SEVERITY = "severity"
    FIRST_DETECTED = "first_detected"
    LAST_SEEN = "last_seen"
    PACKAGE = "package"
    INSTALLED_VERSION = "installed_version"
    FIXED_VERSION = "fixed_version"
    IDENTIFIER = "identifier"
    PROJECT = "project"
    STATUS = "status"
    SLA_REMAINING = "sla_remaining"
    GRACE_REMAINING = "grace_remaining"


@dataclass(frozen=True)
class FindingFilters:
    """Filters accepted by the finding query service.

    Attributes:
        project_id: Optional project ID to limit results.
        scan_target_id: Optional scan target asset ID to limit results.
        asset_id: Optional inventory asset ID to limit results.
        scanner: Optional scanner kind, compared case-insensitively.
        severity: Optional severity, compared case-insensitively.
        identifier: Optional case-insensitive substring matched against identifiers.
        package: Optional case-insensitive substring matched against package names.
        status: Optional finding workflow status.
        present_in_latest_scan: Optional latest-scan presence filter.
        fix_available: Optional filter for findings with a non-empty fixed version.
        open_only: Whether to include only Open findings.
    """

    project_id: str | None = None
    scan_target_id: str | None = None
    asset_id: str | None = None
    scanner: str | None = None
    severity: str | None = None
    identifier: str | None = None
    package: str | None = None
    status: str | FindingStatus | None = None
    present_in_latest_scan: bool | None = None
    fix_available: bool | None = None
    open_only: bool = False


@dataclass(frozen=True)
class FindingSort:
    """Sort configuration for finding rows.

    Attributes:
        key: Field or computed value used for ordering.
        direction: Sort direction.
    """

    key: SortKey = SortKey.LAST_SEEN
    direction: SortDirection = SortDirection.DESC


@dataclass(frozen=True)
class FindingRow:
    """One finding row with joined context and calculated SLA state.

    Attributes:
        project: Project that owns the finding.
        target: Scan target asset for the finding.
        finding: Raw scanner finding occurrence.
        group: Optional project-level vulnerability group.
        sla_state: Calculated SLA state for the finding.
    """

    project: Project
    target: AssetNode
    finding: RawFindingInstance
    group: ProjectVulnerabilityGroup | None
    sla_state: SlaState


@dataclass(frozen=True)
class FindingDetail:
    """Detailed finding context for a single raw finding instance.

    Attributes:
        project: Project that owns the finding.
        target: Scan target asset for the finding.
        finding: Raw scanner finding occurrence with evidence JSON.
        group: Optional project-level vulnerability group.
        sla_state: Calculated SLA state for the finding.
        comments: Chronological comments and status activity for the finding.
        status_change_requests: Chronological status workflow requests.
    """

    project: Project
    target: AssetNode
    finding: RawFindingInstance
    group: ProjectVulnerabilityGroup | None
    sla_state: SlaState
    comments: list[FindingComment]
    status_change_requests: list[FindingStatusChangeRequest]


def list_findings(
    session: Session,
    *,
    filters: FindingFilters | None = None,
    sort: FindingSort | None = None,
    now: datetime,
) -> list[FindingRow]:
    """List findings with project, target, group, and SLA context.

    Args:
        session: SQLAlchemy session used for querying.
        filters: Optional stored-field and workflow filters.
        sort: Optional row ordering configuration.
        now: Reference timestamp for SLA calculations.

    Returns:
        Finding rows matching the requested filters.
    """

    filters = filters or FindingFilters()
    asset_scan_target_ids = _scan_target_ids_for_asset_filter(session, filters)
    statement = _apply_filters(
        _base_statement(),
        filters,
        asset_scan_target_ids=asset_scan_target_ids,
    )
    rows = [_row_from_tuple(tuple_row, now=now) for tuple_row in session.execute(statement).all()]
    rows = _apply_python_filters(rows, filters)
    return _sort_rows(rows, sort or FindingSort())


def get_finding_detail(
    session: Session,
    finding_id: str,
    *,
    now: datetime,
) -> FindingDetail | None:
    """Load one finding with project, target, group, and SLA context.

    Args:
        session: SQLAlchemy session used for querying.
        finding_id: Raw finding instance ID to load.
        now: Reference timestamp for SLA calculations.

    Returns:
        Detailed finding context, or ``None`` when the ID is unknown.
    """

    result = session.execute(
        _base_statement().where(RawFindingInstance.id == finding_id)
    ).one_or_none()
    if result is None:
        return None

    row = _row_from_tuple(result, now=now)
    return FindingDetail(
        project=row.project,
        target=row.target,
        finding=row.finding,
        group=row.group,
        sla_state=row.sla_state,
        comments=_finding_comments(session, finding_id),
        status_change_requests=_finding_status_change_requests(session, finding_id),
    )


def _finding_comments(session: Session, finding_id: str) -> list[FindingComment]:
    return list(
        session.scalars(
            select(FindingComment)
            .where(FindingComment.finding_id == finding_id)
            .order_by(FindingComment.created_at, FindingComment.id)
        )
    )


def _finding_status_change_requests(
    session: Session,
    finding_id: str,
) -> list[FindingStatusChangeRequest]:
    return list(
        session.scalars(
            select(FindingStatusChangeRequest)
            .where(FindingStatusChangeRequest.finding_id == finding_id)
            .order_by(FindingStatusChangeRequest.created_at, FindingStatusChangeRequest.id)
        )
    )


def _base_statement() -> Select[_FindingJoinRow]:
    return (
        select(RawFindingInstance, Project, AssetNode, ProjectVulnerabilityGroup)
        .join(Project, RawFindingInstance.project_id == Project.id)
        .join(AssetNode, RawFindingInstance.scan_target_id == AssetNode.id)
        .outerjoin(
            ProjectVulnerabilityGroup,
            and_(
                ProjectVulnerabilityGroup.project_id == RawFindingInstance.project_id,
                ProjectVulnerabilityGroup.dedupe_key == RawFindingInstance.primary_identifier,
            ),
        )
    )


def _apply_filters(
    statement: Select[_FindingJoinRow],
    filters: FindingFilters,
    *,
    asset_scan_target_ids: list[str] | None = None,
) -> Select[_FindingJoinRow]:
    """Apply database-backed finding filters to a base query.

    Args:
        statement: Base finding query statement.
        filters: Filter values requested by the caller.
        asset_scan_target_ids: Optional resolved scan target IDs for an asset filter.

    Returns:
        Query statement constrained by supported database filters.
    """

    if filters.project_id is not None:
        statement = statement.where(RawFindingInstance.project_id == filters.project_id)
    if filters.scan_target_id is not None:
        statement = statement.where(RawFindingInstance.scan_target_id == filters.scan_target_id)
    if asset_scan_target_ids is not None:
        if not asset_scan_target_ids:
            statement = statement.where(false())
        else:
            statement = statement.where(
                RawFindingInstance.scan_target_id.in_(asset_scan_target_ids)
            )
    if filters.scanner:
        statement = statement.where(
            func.lower(RawFindingInstance.scanner_kind) == filters.scanner.casefold()
        )
    if filters.severity:
        statement = statement.where(
            func.lower(RawFindingInstance.severity) == filters.severity.casefold()
        )
    if filters.package:
        statement = statement.where(
            func.lower(RawFindingInstance.package_name).like(f"%{filters.package.casefold()}%")
        )
    if filters.status is not None:
        statement = statement.where(RawFindingInstance.status == str(filters.status))
    if filters.present_in_latest_scan is not None:
        statement = statement.where(
            RawFindingInstance.present_in_latest_scan.is_(filters.present_in_latest_scan)
        )
    if filters.fix_available is True:
        statement = statement.where(
            RawFindingInstance.fixed_version.is_not(None),
            RawFindingInstance.fixed_version != "",
        )
    if filters.fix_available is False:
        statement = statement.where(
            (RawFindingInstance.fixed_version.is_(None)) | (RawFindingInstance.fixed_version == "")
        )
    if filters.open_only:
        statement = statement.where(RawFindingInstance.status == FindingStatus.OPEN)
    return statement


def _scan_target_ids_for_asset_filter(
    session: Session,
    filters: FindingFilters,
) -> list[str] | None:
    """Resolve an asset filter into scan target IDs.

    Args:
        session: SQLAlchemy session used for inventory lookup.
        filters: Finding filters that may include an asset and project scope.

    Returns:
        ``None`` when no asset filter is requested, otherwise scan target IDs matching the
        asset. Unknown assets and project mismatches return an empty list.
    """

    if filters.asset_id is None:
        return None

    asset_statement = select(AssetNode).where(AssetNode.id == filters.asset_id)
    if filters.project_id is not None:
        asset_statement = asset_statement.where(AssetNode.project_id == filters.project_id)
    asset = session.scalars(asset_statement).one_or_none()
    if asset is None:
        return []
    if asset.node_type == AssetNodeType.SCAN_TARGET.value:
        return [asset.id]

    project_assets = session.scalars(
        select(AssetNode).where(AssetNode.project_id == asset.project_id)
    ).all()
    children_by_parent: dict[str | None, list[AssetNode]] = {}
    for project_asset in project_assets:
        children_by_parent.setdefault(project_asset.parent_id, []).append(project_asset)

    scan_target_ids: list[str] = []
    stack = [asset.id]
    while stack:
        parent_id = stack.pop()
        for child in children_by_parent.get(parent_id, []):
            if child.node_type == AssetNodeType.SCAN_TARGET.value:
                scan_target_ids.append(child.id)
            stack.append(child.id)
    return scan_target_ids


def _apply_python_filters(
    rows: list[FindingRow],
    filters: FindingFilters,
) -> list[FindingRow]:
    if not filters.identifier:
        return rows

    needle = filters.identifier.casefold()
    return [row for row in rows if _identifier_matches(row.finding, needle)]


def _identifier_matches(finding: RawFindingInstance, needle: str) -> bool:
    candidates = [
        finding.primary_identifier,
        finding.scanner_finding_id,
        finding.dedupe_key,
        *finding.identifiers_json,
    ]
    return any(needle in candidate.casefold() for candidate in candidates if candidate)


def _row_from_tuple(
    tuple_row: Row[_FindingJoinRow],
    *,
    now: datetime,
) -> FindingRow:
    finding, project, target, group = tuple_row
    return FindingRow(
        project=project,
        target=target,
        finding=finding,
        group=group,
        sla_state=calculate_sla_state(project, target, finding, now=now),
    )


def _sort_rows(rows: list[FindingRow], sort: FindingSort) -> list[FindingRow]:
    reverse = sort.direction == SortDirection.DESC
    if sort.key == SortKey.SEVERITY:
        return sorted(
            rows,
            key=lambda row: (
                _severity_rank(row.finding.severity),
                _as_utc(row.finding.last_seen_at),
                row.finding.primary_identifier,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.FIRST_DETECTED:
        return sorted(
            rows,
            key=lambda row: (
                _as_utc(row.finding.first_seen_at),
                row.finding.primary_identifier,
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.LAST_SEEN:
        return sorted(
            rows,
            key=lambda row: (
                _as_utc(row.finding.last_seen_at),
                row.finding.primary_identifier,
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.PACKAGE:
        return sorted(
            rows,
            key=lambda row: (
                (row.finding.package_name or "").casefold(),
                row.finding.primary_identifier,
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.INSTALLED_VERSION:
        return sorted(
            rows,
            key=lambda row: (
                (row.finding.package_version or "").casefold(),
                row.finding.primary_identifier,
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.FIXED_VERSION:
        return sorted(
            rows,
            key=lambda row: (
                row.finding.fixed_version is None or row.finding.fixed_version == "",
                (row.finding.fixed_version or "").casefold(),
                row.finding.primary_identifier,
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.IDENTIFIER:
        return sorted(
            rows,
            key=lambda row: (
                row.finding.primary_identifier.casefold(),
                (row.finding.package_name or "").casefold(),
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.PROJECT:
        return sorted(
            rows,
            key=lambda row: (
                row.project.name.casefold(),
                row.target.path.casefold(),
                row.finding.primary_identifier.casefold(),
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.STATUS:
        return sorted(
            rows,
            key=lambda row: (
                str(row.finding.status).casefold(),
                row.finding.primary_identifier.casefold(),
                row.finding.id,
            ),
            reverse=reverse,
        )
    if sort.key == SortKey.SLA_REMAINING:
        return sorted(
            rows,
            key=lambda row: (
                row.sla_state.remaining_days is None,
                _sla_remaining_rank(row.sla_state.remaining_days, sort.direction),
                row.finding.primary_identifier,
                row.finding.id,
            ),
        )
    if sort.key == SortKey.GRACE_REMAINING:
        return sorted(
            rows,
            key=lambda row: (
                row.sla_state.grace_remaining_days is None,
                _sla_remaining_rank(row.sla_state.grace_remaining_days, sort.direction),
                row.finding.primary_identifier,
                row.finding.id,
            ),
        )
    return rows


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.upper(), _SEVERITY_RANK["UNKNOWN"])


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _sla_remaining_rank(remaining_days: int | None, direction: SortDirection) -> int:
    if remaining_days is None:
        return 0
    if direction == SortDirection.DESC:
        return -remaining_days
    return remaining_days
