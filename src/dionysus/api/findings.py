"""JSON API routes for finding browsing and detail data."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.audit import record_audit_event
from dionysus.findings.queries import (
    FindingDetail,
    FindingFilters,
    FindingRow,
    FindingSort,
    SortDirection,
    SortKey,
    get_finding_detail,
    list_findings,
    with_release_detail,
)
from dionysus.findings.workflow import (
    add_finding_comment,
    approve_finding_status_request,
    change_finding_status,
    reject_finding_status_request,
)
from dionysus.identity.actors import AuthenticatedActor, get_authenticated_actor
from dionysus.identity.authorization import actor_has_permission, ensure_actor_permission
from dionysus.models.findings import (
    FindingComment,
    FindingStatus,
    FindingStatusChangeRequest,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
)
from dionysus.models.identity import MachineCredential, User
from dionysus.security.settings import effective_peer_review_required

router = APIRouter(prefix="/api/findings", tags=["findings"])
authenticated_actor_dependency = Depends(get_authenticated_actor)
FINDING_COMMENT_PERMISSION = "finding:comment"
FINDING_VIEW_PERMISSION = "finding:view"
FINDING_STATUS_CHANGE_REQUEST_PERMISSION = "finding:status_change:request"
FINDING_STATUS_CHANGE_APPROVE_PERMISSION = "finding:status_change:approve"


class ProjectGroupResponse(BaseModel):
    """Project-level vulnerability group metadata for one finding."""

    model_config = ConfigDict(extra="forbid")

    id: str
    primary_identifier: str
    additional_identifiers: list[str]
    status: str
    first_detected_at: datetime


class FindingRowResponse(BaseModel):
    """Normalized finding row for React list and table views."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    project_name: str
    scan_target_id: str
    scan_target_name: str
    scan_target_path: str
    scan_target_ref: str | None
    scanner: str
    primary_identifier: str
    additional_identifiers: list[str]
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    severity: str
    cvss: dict[str, Any]
    status: str
    first_detected_at: datetime
    last_seen_at: datetime
    present_in_latest_scan: bool
    sla_active: bool
    sla_remaining_days: int | None
    grace_remaining_days: int | None
    sla_status: str
    sla_reason: str | None
    sla_days: int | None
    grace_days: int | None
    include_in_sla_reports: bool


class FindingListResponse(BaseModel):
    """Response body for finding list queries."""

    model_config = ConfigDict(extra="forbid")

    rows: list[FindingRowResponse]


class FindingCommentCreateRequest(BaseModel):
    """Request body for creating a finding comment."""

    model_config = ConfigDict(extra="forbid")

    body: str


class FindingStatusUpdateRequest(BaseModel):
    """Request body for changing or requesting a finding status."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    comment: str
    require_peer_review: bool = False


class FindingStatusApprovalRequest(BaseModel):
    """Request body for approving a pending finding status change."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = None


class FindingStatusRejectionRequest(BaseModel):
    """Request body for rejecting a pending finding status change."""

    model_config = ConfigDict(extra="forbid")

    comment: str


class FindingCommentResponse(BaseModel):
    """Compact finding comment or activity response."""

    model_config = ConfigDict(extra="forbid")

    id: str
    body: str
    author_principal_type: str
    author_principal_id: str
    author_display: str | None
    created_at: datetime
    is_system: bool
    status_from: str | None
    status_to: str | None


class FindingStatusChangeRequestResponse(BaseModel):
    """Compact finding status workflow response."""

    model_config = ConfigDict(extra="forbid")

    id: str
    requester_principal_type: str
    requester_principal_id: str
    requester_display: str | None
    reviewer_principal_type: str | None
    reviewer_principal_id: str | None
    reviewer_display: str | None
    from_status: str
    to_status: str
    state: str
    comment: str | None
    decision_comment: str | None
    created_at: datetime
    decided_at: datetime | None


class FindingReleaseContextResponse(BaseModel):
    """Release inheritance context for a release-scoped finding."""

    model_config = ConfigDict(extra="forbid")

    scope_asset_id: str
    scope_path: str
    version_asset_id: str
    version: str


class FindingRelatedOccurrenceResponse(BaseModel):
    """Related release occurrence for a finding detail response."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    release_version: str
    project_name: str
    scan_target_name: str
    scan_target_path: str
    status: str
    present_in_latest_scan: bool
    installed_version: str | None
    fixed_version: str | None


class FindingDetailResponse(FindingRowResponse):
    """Detailed finding context and evidence for React detail views."""

    model_config = ConfigDict(extra="forbid")

    scanner_finding_id: str
    dedupe_key: str
    identifiers: list[str]
    references: list[str]
    description: str | None
    artifact_name: str | None
    artifact_type: str | None
    artifact_path: str | None
    source_evidence: dict[str, Any]
    project_group: ProjectGroupResponse | None
    release_context: FindingReleaseContextResponse | None
    related_occurrences: list[FindingRelatedOccurrenceResponse]
    comments: list[FindingCommentResponse]
    status_change_requests: list[FindingStatusChangeRequestResponse]


@router.get("", response_model=FindingListResponse)
def findings_list_api(
    request: Request,
    actor: AuthenticatedActor = authenticated_actor_dependency,
    project_id: str | None = None,
    scan_target_id: str | None = None,
    asset_id: str | None = None,
    scanner: str | None = None,
    severity: str | None = None,
    identifier: str | None = None,
    package: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    present_in_latest_scan: str | None = None,
    fix_available: str | None = None,
    sort: str = SortKey.LAST_SEEN.value,
    direction: str = SortDirection.DESC.value,
) -> FindingListResponse:
    """Return normalized finding rows for the React frontend.

    Args:
        request: Incoming request containing application state.
        actor: Authenticated request actor required for access.
        project_id: Optional project ID filter.
        scan_target_id: Optional scan target asset ID filter.
        asset_id: Optional inventory asset ID filter.
        scanner: Optional scanner kind filter.
        severity: Optional severity filter.
        identifier: Optional identifier substring filter.
        package: Optional package substring filter.
        status_filter: Optional finding workflow status filter.
        present_in_latest_scan: Optional latest-scan presence filter.
        fix_available: Optional filter for findings with a non-empty fixed version.
        sort: Sort key accepted by the finding query service.
        direction: Sort direction accepted by the finding query service.

    Returns:
        JSON-serializable finding rows matching the requested filters.
    """

    filters = FindingFilters(
        project_id=_blank_to_none(project_id),
        scan_target_id=_blank_to_none(scan_target_id),
        asset_id=_blank_to_none(asset_id),
        scanner=_blank_to_none(scanner),
        severity=_blank_to_none(severity),
        identifier=_blank_to_none(identifier),
        package=_blank_to_none(package),
        status=_status_or_none(status_filter),
        present_in_latest_scan=_bool_or_none(present_in_latest_scan),
        fix_available=_bool_or_none(fix_available, field_name="fix_available"),
    )
    finding_sort = FindingSort(
        key=_sort_key_or_400(sort),
        direction=_sort_direction_or_400(direction),
    )
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        rows = list_findings(
            session,
            filters=filters,
            sort=finding_sort,
            now=datetime.now(UTC),
        )
        visible_rows = [
            row
            for row in rows
            if actor_has_permission(
                session,
                actor=actor,
                permission=FINDING_VIEW_PERMISSION,
                scope_type="project",
                scope_id=row.project.id,
            )
        ]
        return FindingListResponse(rows=[_row_response(row) for row in visible_rows])


@router.get("/{finding_id}", response_model=FindingDetailResponse)
def finding_detail_api(
    request: Request,
    finding_id: str,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> FindingDetailResponse:
    """Return joined finding detail and scanner evidence for the React frontend.

    Args:
        request: Incoming request containing application state.
        finding_id: Raw finding instance UUID string.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable finding detail with joined project and target context.

    Raises:
        HTTPException: If the finding ID is unknown.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        detail = get_finding_detail(session, finding_id, now=datetime.now(UTC))
        if detail is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        _ensure_finding_permission(
            session,
            actor=actor,
            finding=detail.finding,
            permission=FINDING_VIEW_PERMISSION,
        )
        detail = with_release_detail(session, detail)
        return _detail_response(
            detail,
            principal_displays=_principal_display_map(
                session,
                comments=detail.comments,
                status_requests=detail.status_change_requests,
            ),
        )


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentResponse,
    status_code=status.HTTP_201_CREATED,
)
def finding_comment_create_api(
    request: Request,
    finding_id: str,
    payload: FindingCommentCreateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> FindingCommentResponse:
    """Create a human comment on a finding.

    Args:
        request: Incoming request containing application state.
        finding_id: Raw finding instance UUID string.
        payload: Comment creation body.
        actor: Authenticated request actor creating the comment.

    Returns:
        JSON-serializable created comment.

    Raises:
        HTTPException: If the finding ID is unknown or the comment is blank.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        finding = session.get(RawFindingInstance, finding_id)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        _ensure_finding_permission(
            session,
            actor=actor,
            finding=finding,
            permission=FINDING_COMMENT_PERMISSION,
        )
        try:
            comment = add_finding_comment(
                session,
                finding,
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                body=payload.body,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.flush()
        response = _comment_response(comment, author_display=actor.display_name)
        record_audit_event(
            session,
            event_type="finding.comment.created",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="finding",
            target_id=finding.id,
            project_id=finding.project_id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"comment_id": comment.id},
        )
        session.commit()
        return response


@router.post("/{finding_id}/status", response_model=FindingDetailResponse)
def finding_status_update_api(
    request: Request,
    finding_id: str,
    payload: FindingStatusUpdateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> FindingDetailResponse:
    """Change or request review for a finding status.

    Args:
        request: Incoming request containing application state.
        finding_id: Raw finding instance UUID string.
        payload: Status transition request body.
        actor: Authenticated request actor requesting the transition.

    Returns:
        Updated finding detail with compact activity.

    Raises:
        HTTPException: If the finding ID is unknown or validation fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        finding = session.get(RawFindingInstance, finding_id)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        _ensure_finding_permission(
            session,
            actor=actor,
            finding=finding,
            permission=FINDING_STATUS_CHANGE_REQUEST_PERMISSION,
        )
        try:
            require_peer_review = effective_peer_review_required(
                session,
                finding=finding,
                requested_peer_review=payload.require_peer_review,
            )
            status_result = change_finding_status(
                session,
                finding,
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                to_status=payload.status,
                comment=payload.comment,
                require_peer_review=require_peer_review,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.flush()
        detail = get_finding_detail(session, finding_id, now=datetime.now(UTC))
        if detail is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        if _actor_can_view_finding(session, actor=actor, finding=finding):
            detail = with_release_detail(session, detail)
        response = _detail_response(
            detail,
            principal_displays=_principal_display_map(
                session,
                comments=detail.comments,
                status_requests=detail.status_change_requests,
            ),
        )
        record_audit_event(
            session,
            event_type=(
                "finding.status.changed" if status_result.applied else "finding.status.requested"
            ),
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="finding",
            target_id=finding.id,
            project_id=finding.project_id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "request_id": status_result.request.id,
                "comment_id": status_result.comment.id,
                "from_status": status_result.request.from_status,
                "to_status": status_result.request.to_status,
            },
        )
        session.commit()
        return response


@router.post(
    "/{finding_id}/status-requests/{request_id}/approve",
    response_model=FindingDetailResponse,
)
def finding_status_request_approve_api(
    request: Request,
    finding_id: str,
    request_id: str,
    payload: FindingStatusApprovalRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> FindingDetailResponse:
    """Approve a pending peer-reviewed finding status change.

    Args:
        request: Incoming request containing application state.
        finding_id: Raw finding instance UUID string.
        request_id: Status change request UUID string.
        payload: Optional approval decision comment.
        actor: Authenticated request actor approving the transition.

    Returns:
        Updated finding detail with compact activity.

    Raises:
        HTTPException: If the finding or request is unknown, or validation fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        finding = session.get(RawFindingInstance, finding_id)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        _ensure_finding_permission(
            session,
            actor=actor,
            finding=finding,
            permission=FINDING_STATUS_CHANGE_APPROVE_PERMISSION,
        )
        status_request = _status_request_for_finding_or_404(session, finding_id, request_id)
        try:
            approve_finding_status_request(
                session,
                finding,
                status_request,
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                comment=payload.comment,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.flush()
        response = _updated_detail_or_404(
            session,
            finding_id,
            include_release_detail=_actor_can_view_finding(session, actor=actor, finding=finding),
        )
        record_audit_event(
            session,
            event_type="finding.status.approved",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="finding",
            target_id=finding.id,
            project_id=finding.project_id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata=_status_review_audit_metadata(status_request),
        )
        session.commit()
        return response


@router.post(
    "/{finding_id}/status-requests/{request_id}/reject",
    response_model=FindingDetailResponse,
)
def finding_status_request_reject_api(
    request: Request,
    finding_id: str,
    request_id: str,
    payload: FindingStatusRejectionRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> FindingDetailResponse:
    """Reject a pending peer-reviewed finding status change.

    Args:
        request: Incoming request containing application state.
        finding_id: Raw finding instance UUID string.
        request_id: Status change request UUID string.
        payload: Required rejection decision comment.
        actor: Authenticated request actor rejecting the transition.

    Returns:
        Updated finding detail with compact activity.

    Raises:
        HTTPException: If the finding or request is unknown, or validation fails.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        finding = session.get(RawFindingInstance, finding_id)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        _ensure_finding_permission(
            session,
            actor=actor,
            finding=finding,
            permission=FINDING_STATUS_CHANGE_APPROVE_PERMISSION,
        )
        status_request = _status_request_for_finding_or_404(session, finding_id, request_id)
        try:
            reject_finding_status_request(
                session,
                finding,
                status_request,
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                comment=payload.comment,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        session.flush()
        response = _updated_detail_or_404(
            session,
            finding_id,
            include_release_detail=_actor_can_view_finding(session, actor=actor, finding=finding),
        )
        record_audit_event(
            session,
            event_type="finding.status.rejected",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="finding",
            target_id=finding.id,
            project_id=finding.project_id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata=_status_review_audit_metadata(status_request),
        )
        session.commit()
        return response


def _row_response(row: FindingRow) -> FindingRowResponse:
    finding = row.finding
    return FindingRowResponse(
        id=finding.id,
        project_id=row.project.id,
        project_name=row.project.name,
        scan_target_id=row.target.id,
        scan_target_name=row.target.name,
        scan_target_path=row.target.path,
        scan_target_ref=row.target.target_ref,
        scanner=finding.scanner_kind,
        primary_identifier=finding.primary_identifier,
        additional_identifiers=_additional_identifiers(finding),
        package_name=finding.package_name,
        installed_version=finding.package_version,
        fixed_version=finding.fixed_version,
        severity=finding.severity,
        cvss=finding.cvss_json,
        status=finding.status,
        first_detected_at=_as_utc(finding.first_seen_at),
        last_seen_at=_as_utc(finding.last_seen_at),
        present_in_latest_scan=finding.present_in_latest_scan,
        sla_active=row.sla_state.active,
        sla_remaining_days=row.sla_state.remaining_days,
        grace_remaining_days=row.sla_state.grace_remaining_days,
        sla_status=row.sla_state.status,
        sla_reason=row.sla_state.reason,
        sla_days=row.sla_state.sla_days,
        grace_days=row.sla_state.grace_days,
        include_in_sla_reports=row.sla_state.include_in_sla_reports,
    )


def _ensure_finding_permission(
    session: Session,
    *,
    actor: AuthenticatedActor,
    finding: RawFindingInstance,
    permission: str,
) -> None:
    ensure_actor_permission(
        session,
        actor=actor,
        permission=permission,
        scope_type="project",
        scope_id=finding.project_id,
    )


def _actor_can_view_finding(
    session: Session,
    *,
    actor: AuthenticatedActor,
    finding: RawFindingInstance,
) -> bool:
    return actor_has_permission(
        session,
        actor=actor,
        permission=FINDING_VIEW_PERMISSION,
        scope_type="project",
        scope_id=finding.project_id,
    )


def _detail_response(
    detail: FindingDetail,
    *,
    principal_displays: dict[tuple[str, str], str | None] | None = None,
) -> FindingDetailResponse:
    row = FindingRow(
        project=detail.project,
        target=detail.target,
        finding=detail.finding,
        group=detail.group,
        sla_state=detail.sla_state,
    )
    base = _row_response(row)
    finding = detail.finding
    return FindingDetailResponse(
        **base.model_dump(),
        scanner_finding_id=finding.scanner_finding_id,
        dedupe_key=finding.dedupe_key,
        identifiers=list(finding.identifiers_json),
        references=list(finding.references_json),
        description=_source_description(finding.source_json),
        artifact_name=finding.artifact_name,
        artifact_type=finding.artifact_type,
        artifact_path=finding.artifact_path,
        source_evidence=finding.source_json,
        project_group=_project_group_response(detail.group),
        release_context=(
            None
            if detail.release_context is None
            else FindingReleaseContextResponse(
                scope_asset_id=detail.release_context.scope_asset_id,
                scope_path=detail.release_context.scope_path,
                version_asset_id=detail.release_context.version_asset_id,
                version=detail.release_context.version,
            )
        ),
        related_occurrences=[
            FindingRelatedOccurrenceResponse(
                finding_id=occurrence.finding_id,
                release_version=occurrence.release_version,
                project_name=occurrence.project_name,
                scan_target_name=occurrence.scan_target_name,
                scan_target_path=occurrence.scan_target_path,
                status=occurrence.status,
                present_in_latest_scan=occurrence.present_in_latest_scan,
                installed_version=occurrence.installed_version,
                fixed_version=occurrence.fixed_version,
            )
            for occurrence in detail.related_occurrences
        ],
        comments=[
            _comment_response(
                comment,
                author_display=_display_for(
                    principal_displays,
                    comment.author_principal_type,
                    comment.author_principal_id,
                ),
            )
            for comment in detail.comments
        ],
        status_change_requests=[
            _status_change_request_response(
                status_request,
                requester_display=_display_for(
                    principal_displays,
                    status_request.requester_principal_type,
                    status_request.requester_principal_id,
                ),
                reviewer_display=_display_for(
                    principal_displays,
                    status_request.reviewer_principal_type,
                    status_request.reviewer_principal_id,
                ),
            )
            for status_request in detail.status_change_requests
        ],
    )


def _comment_response(
    comment: FindingComment,
    *,
    author_display: str | None = None,
) -> FindingCommentResponse:
    return FindingCommentResponse(
        id=comment.id,
        body=comment.body,
        author_principal_type=comment.author_principal_type,
        author_principal_id=comment.author_principal_id,
        author_display=author_display,
        created_at=_as_utc(comment.created_at),
        is_system=comment.is_system,
        status_from=comment.status_from,
        status_to=comment.status_to,
    )


def _status_change_request_response(
    status_request: FindingStatusChangeRequest,
    *,
    requester_display: str | None = None,
    reviewer_display: str | None = None,
) -> FindingStatusChangeRequestResponse:
    return FindingStatusChangeRequestResponse(
        id=status_request.id,
        requester_principal_type=status_request.requester_principal_type,
        requester_principal_id=status_request.requester_principal_id,
        requester_display=requester_display,
        reviewer_principal_type=status_request.reviewer_principal_type,
        reviewer_principal_id=status_request.reviewer_principal_id,
        reviewer_display=reviewer_display,
        from_status=status_request.from_status,
        to_status=status_request.to_status,
        state=status_request.state,
        comment=status_request.comment,
        decision_comment=status_request.decision_comment,
        created_at=_as_utc(status_request.created_at),
        decided_at=(
            _as_utc(status_request.decided_at) if status_request.decided_at is not None else None
        ),
    )


def _principal_display_map(
    session: Session,
    *,
    comments: list[FindingComment],
    status_requests: list[FindingStatusChangeRequest],
) -> dict[tuple[str, str], str | None]:
    """Resolve activity principals to display names in batches.

    Args:
        session: SQLAlchemy session used for principal lookup.
        comments: Finding comments whose authors should be resolved.
        status_requests: Workflow requests whose requester and reviewer
            principals should be resolved.

    Returns:
        Mapping from ``(principal_type, principal_id)`` to display text.
    """

    user_ids: set[str] = set()
    machine_ids: set[str] = set()
    for principal_type, principal_id in _activity_principal_refs(comments, status_requests):
        if principal_type == "user":
            user_ids.add(principal_id)
        elif principal_type == "machine":
            machine_ids.add(principal_id)

    displays: dict[tuple[str, str], str | None] = {}
    if user_ids:
        users = session.scalars(select(User).where(User.id.in_(user_ids))).all()
        displays.update(
            {("user", user.id): user.display_name.strip() or user.username for user in users}
        )
    if machine_ids:
        credentials = session.scalars(
            select(MachineCredential).where(MachineCredential.id.in_(machine_ids))
        ).all()
        displays.update({("machine", credential.id): credential.name for credential in credentials})
    return displays


def _activity_principal_refs(
    comments: list[FindingComment],
    status_requests: list[FindingStatusChangeRequest],
) -> set[tuple[str, str]]:
    """Collect non-null principal references used by finding activity.

    Args:
        comments: Finding comments to scan for author principals.
        status_requests: Workflow requests to scan for requester and reviewer
            principals.

    Returns:
        Unique ``(principal_type, principal_id)`` references.
    """

    refs = {(comment.author_principal_type, comment.author_principal_id) for comment in comments}
    for status_request in status_requests:
        refs.add((status_request.requester_principal_type, status_request.requester_principal_id))
        if (
            status_request.reviewer_principal_type is not None
            and status_request.reviewer_principal_id is not None
        ):
            refs.add((status_request.reviewer_principal_type, status_request.reviewer_principal_id))
    return refs


def _display_for(
    displays: dict[tuple[str, str], str | None] | None,
    principal_type: str | None,
    principal_id: str | None,
) -> str | None:
    """Return a resolved display name for one principal reference.

    Args:
        displays: Precomputed display-name mapping.
        principal_type: Principal type to resolve.
        principal_id: Principal ID to resolve.

    Returns:
        Display text when the principal is known, otherwise ``None``.
    """

    if displays is None or principal_type is None or principal_id is None:
        return None
    return displays.get((principal_type, principal_id))


def _project_group_response(
    group: ProjectVulnerabilityGroup | None,
) -> ProjectGroupResponse | None:
    if group is None:
        return None
    return ProjectGroupResponse(
        id=group.id,
        primary_identifier=group.primary_identifier,
        additional_identifiers=list(group.additional_identifiers_json),
        status=group.status,
        first_detected_at=_as_utc(group.first_detected_at),
    )


def _status_request_for_finding_or_404(
    session: Session,
    finding_id: str,
    request_id: str,
) -> FindingStatusChangeRequest:
    status_request = session.scalars(
        select(FindingStatusChangeRequest).where(
            FindingStatusChangeRequest.id == request_id,
            FindingStatusChangeRequest.finding_id == finding_id,
        )
    ).one_or_none()
    if status_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Status change request not found",
        )
    return status_request


def _updated_detail_or_404(
    session: Session,
    finding_id: str,
    *,
    include_release_detail: bool,
) -> FindingDetailResponse:
    detail = get_finding_detail(session, finding_id, now=datetime.now(UTC))
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    if include_release_detail:
        detail = with_release_detail(session, detail)
    return _detail_response(
        detail,
        principal_displays=_principal_display_map(
            session,
            comments=detail.comments,
            status_requests=detail.status_change_requests,
        ),
    )


def _status_review_audit_metadata(
    status_request: FindingStatusChangeRequest,
) -> dict[str, str]:
    return {
        "request_id": status_request.id,
        "from_status": status_request.from_status,
        "to_status": status_request.to_status,
    }


def _additional_identifiers(finding: RawFindingInstance) -> list[str]:
    primary = finding.primary_identifier.casefold()
    return [
        identifier for identifier in finding.identifiers_json if identifier.casefold() != primary
    ]


def _source_description(source: dict[str, Any]) -> str | None:
    description = source.get("description")
    if isinstance(description, str) and description.strip():
        return description.strip()
    title = source.get("title")
    return title.strip() if isinstance(title, str) and title.strip() else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _status_or_none(value: str | None) -> FindingStatus | None:
    value = _blank_to_none(value)
    if value is None:
        return None
    try:
        return FindingStatus(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported finding status",
        ) from exc


def _bool_or_none(value: str | None, *, field_name: str = "present_in_latest_scan") -> bool | None:
    value = _blank_to_none(value)
    if value is None:
        return None
    normalized = value.casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"{field_name} must be true or false",
    )


def _sort_key_or_400(value: str) -> SortKey:
    try:
        return SortKey(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported finding sort",
        ) from exc


def _sort_direction_or_400(value: str) -> SortDirection:
    try:
        return SortDirection(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported finding sort direction",
        ) from exc


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None
