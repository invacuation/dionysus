"""Workflow services for finding comments and status changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from dionysus.findings.release_inheritance import record_release_status_decision
from dionysus.models.findings import (
    FindingComment,
    FindingStatus,
    FindingStatusChangeRequest,
    FindingStatusChangeState,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
)


@dataclass(frozen=True)
class FindingStatusChangeResult:
    """Result of creating a finding status workflow transition."""

    request: FindingStatusChangeRequest
    comment: FindingComment
    applied: bool


def add_finding_comment(
    session: Session,
    finding: RawFindingInstance,
    *,
    actor_principal_type: str,
    actor_principal_id: str,
    body: str,
    is_system: bool = False,
) -> FindingComment:
    """Create a comment on a raw finding.

    Args:
        session: SQLAlchemy session used for persistence.
        finding: Raw finding instance receiving the comment.
        actor_principal_type: Type of principal creating the comment.
        actor_principal_id: Principal ID creating the comment.
        body: Comment body text; surrounding whitespace is trimmed.
        is_system: Whether the comment was emitted by system workflow logic.

    Returns:
        The pending ``FindingComment`` model.

    Raises:
        ValueError: If ``body`` is blank.
    """

    comment_body = _required_body(body, "Comment body is required")
    comment = FindingComment(
        finding=finding,
        project_id=finding.project_id,
        author_principal_type=str(actor_principal_type),
        author_principal_id=actor_principal_id,
        body=comment_body,
        is_system=is_system,
    )
    session.add(comment)
    return comment


def change_finding_status(
    session: Session,
    finding: RawFindingInstance,
    *,
    actor_principal_type: str,
    actor_principal_id: str,
    to_status: str | FindingStatus,
    comment: str,
    require_peer_review: bool = False,
    now: datetime | None = None,
) -> FindingStatusChangeResult:
    """Create or apply a raw finding status transition.

    Immediate transitions update the raw finding and matching project
    vulnerability group. Peer-review transitions create a pending workflow
    request and activity comment without mutating status. Future approval
    endpoints must prevent requesters from approving their own changes.

    Args:
        session: SQLAlchemy session used for persistence.
        finding: Raw finding instance whose status should change.
        actor_principal_type: Type of principal requesting the change.
        actor_principal_id: Principal ID requesting the change.
        to_status: Target finding status.
        comment: Request or transition comment. Blank is only allowed for
            no-op/open transitions.
        require_peer_review: Whether to leave the transition pending review.
        now: Optional decision timestamp for immediate transitions.

    Returns:
        The created workflow request, activity comment, and applied flag.

    Raises:
        ValueError: If a non-open status change is missing a comment.
    """

    target_status = FindingStatus(to_status)
    from_status = FindingStatus(finding.status)
    trimmed_comment = comment.strip()
    if target_status != from_status and target_status != FindingStatus.OPEN:
        trimmed_comment = _required_body(comment, "Status change comment is required")

    decision_time = now or datetime.now(UTC)
    applied = not require_peer_review
    request = FindingStatusChangeRequest(
        finding=finding,
        project_id=finding.project_id,
        requester_principal_type=str(actor_principal_type),
        requester_principal_id=actor_principal_id,
        from_status=from_status,
        to_status=target_status,
        state=(FindingStatusChangeState.APPROVED if applied else FindingStatusChangeState.PENDING),
        comment=trimmed_comment or None,
        decided_at=decision_time if applied else None,
    )
    session.add(request)

    activity_comment = FindingComment(
        finding=finding,
        project_id=finding.project_id,
        author_principal_type=str(actor_principal_type),
        author_principal_id=actor_principal_id,
        body=trimmed_comment,
        is_system=False,
        status_from=from_status,
        status_to=target_status,
    )
    session.add(activity_comment)

    if applied:
        finding.status = target_status
        group = _matching_project_group(session, finding)
        if group is not None:
            group.status = target_status
        record_release_status_decision(
            session,
            finding=finding,
            status=target_status,
            comment=activity_comment,
            request=request,
            decided_at=decision_time,
        )

    return FindingStatusChangeResult(
        request=request,
        comment=activity_comment,
        applied=applied,
    )


def approve_finding_status_request(
    session: Session,
    finding: RawFindingInstance,
    request: FindingStatusChangeRequest,
    *,
    actor_principal_type: str,
    actor_principal_id: str,
    comment: str | None = None,
    now: datetime | None = None,
) -> FindingStatusChangeRequest:
    """Approve a pending status request and apply its target status.

    Args:
        session: SQLAlchemy session used for persistence.
        finding: Raw finding instance owning the status request.
        request: Pending status request being approved.
        actor_principal_type: Type of principal making the decision.
        actor_principal_id: Principal ID making the decision.
        comment: Optional approval decision comment.
        now: Optional decision timestamp.

    Returns:
        The updated workflow request.

    Raises:
        ValueError: If the request is not pending or the requester is
            attempting to review their own status change.
    """

    _validate_review_allowed(request, actor_principal_type, actor_principal_id)
    request.state = FindingStatusChangeState.APPROVED
    request.reviewer_principal_type = str(actor_principal_type)
    request.reviewer_principal_id = actor_principal_id
    request.decision_comment = _optional_body(comment)
    request.decided_at = now or datetime.now(UTC)

    finding.status = FindingStatus(request.to_status)
    group = _matching_project_group(session, finding)
    if group is not None:
        group.status = FindingStatus(request.to_status)
    record_release_status_decision(
        session,
        finding=finding,
        status=FindingStatus(request.to_status),
        request=request,
        decided_at=request.decided_at,
    )

    return request


def reject_finding_status_request(
    _session: Session,
    _finding: RawFindingInstance,
    request: FindingStatusChangeRequest,
    *,
    actor_principal_type: str,
    actor_principal_id: str,
    comment: str,
    now: datetime | None = None,
) -> FindingStatusChangeRequest:
    """Reject a pending status request without changing finding status.

    Args:
        _session: SQLAlchemy session used for persistence.
        _finding: Raw finding instance owning the status request.
        request: Pending status request being rejected.
        actor_principal_type: Type of principal making the decision.
        actor_principal_id: Principal ID making the decision.
        comment: Required rejection decision comment.
        now: Optional decision timestamp.

    Returns:
        The updated workflow request.

    Raises:
        ValueError: If the request is not pending, the requester is attempting
            to review their own status change, or the rejection comment is
            blank.
    """

    _validate_review_allowed(request, actor_principal_type, actor_principal_id)
    request.state = FindingStatusChangeState.REJECTED
    request.reviewer_principal_type = str(actor_principal_type)
    request.reviewer_principal_id = actor_principal_id
    request.decision_comment = _required_body(comment, "Decision comment is required")
    request.decided_at = now or datetime.now(UTC)
    return request


def _required_body(body: str, message: str) -> str:
    stripped = body.strip()
    if not stripped:
        raise ValueError(message)
    return stripped


def _optional_body(body: str | None) -> str | None:
    if body is None:
        return None
    stripped = body.strip()
    return stripped or None


def _validate_review_allowed(
    request: FindingStatusChangeRequest,
    actor_principal_type: str,
    actor_principal_id: str,
) -> None:
    if request.state != FindingStatusChangeState.PENDING:
        raise ValueError("Status change request is not pending")
    if (
        request.requester_principal_type == str(actor_principal_type)
        and request.requester_principal_id == actor_principal_id
    ):
        raise ValueError("Requester cannot review their own status change")


def _matching_project_group(
    session: Session,
    finding: RawFindingInstance,
) -> ProjectVulnerabilityGroup | None:
    return session.scalars(
        select(ProjectVulnerabilityGroup).where(
            and_(
                ProjectVulnerabilityGroup.project_id == finding.project_id,
                ProjectVulnerabilityGroup.dedupe_key == finding.primary_identifier,
            )
        )
    ).one_or_none()
