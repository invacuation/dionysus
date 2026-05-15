from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.findings.workflow import (
    add_finding_comment,
    approve_finding_status_request,
    change_finding_status,
    reject_finding_status_request,
)
from dionysus.imports.persistence import import_trivy_report
from dionysus.models.findings import (
    FindingComment,
    FindingStatus,
    FindingStatusChangeRequest,
    FindingStatusChangeState,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project
from dionysus.security.settings import (
    effective_peer_review_required,
    get_security_settings,
)

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _import_project(session: Session) -> Project:
    project = Project(slug="alpha", name="Alpha")
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api",
        path="images/api",
        target_ref="registry.example.test/dionysus/api:2026.05.07",
    )
    session.add_all([project, target])
    session.flush()
    import_trivy_report(
        session,
        project=project,
        scan_target=target,
        payload=FIXTURE.read_bytes(),
        now=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
    )
    return project


def _openssl_finding(session: Session, project: Project) -> RawFindingInstance:
    return session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == project.id,
            RawFindingInstance.package_name == "openssl",
        )
    ).one()


def test_add_finding_comment_rejects_blank_body(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)

    with pytest.raises(ValueError, match="Comment body is required"):
        add_finding_comment(
            db_session,
            finding,
            actor_principal_type="user",
            actor_principal_id="user-1",
            body="  ",
        )


def test_add_finding_comment_persists_author_and_trimmed_body(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)

    comment = add_finding_comment(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="user-1",
        body="  Needs validation from app owner.  ",
    )
    db_session.flush()

    persisted = db_session.get(FindingComment, comment.id)
    assert persisted is not None
    assert persisted.project_id == project.id
    assert persisted.finding_id == finding.id
    assert persisted.author_principal_type == "user"
    assert persisted.author_principal_id == "user-1"
    assert persisted.body == "Needs validation from app owner."
    assert persisted.is_system is False
    assert persisted.status_from is None
    assert persisted.status_to is None


def test_change_to_non_open_requires_comment(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)

    with pytest.raises(ValueError, match="Status change comment is required"):
        change_finding_status(
            db_session,
            finding,
            actor_principal_type="user",
            actor_principal_id="user-1",
            to_status=FindingStatus.FIXED,
            comment="",
        )


def test_change_status_applies_immediately_and_emits_activity(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    group = db_session.scalars(
        select(ProjectVulnerabilityGroup).where(
            ProjectVulnerabilityGroup.project_id == project.id,
            ProjectVulnerabilityGroup.dedupe_key == finding.primary_identifier,
        )
    ).one()

    result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="user-1",
        to_status=FindingStatus.FIXED,
        comment="Patched in image 2026.05.08.",
        now=datetime(2026, 5, 8, 10, 0, tzinfo=UTC),
    )
    db_session.flush()

    assert finding.status == FindingStatus.FIXED
    assert group.status == FindingStatus.FIXED
    assert result.request.state == FindingStatusChangeState.APPROVED
    assert result.request.from_status == FindingStatus.OPEN
    assert result.request.to_status == FindingStatus.FIXED
    assert result.request.decided_at == datetime(2026, 5, 8, 10, 0, tzinfo=UTC)
    assert result.comment.body == "Patched in image 2026.05.08."
    assert result.comment.status_from == FindingStatus.OPEN
    assert result.comment.status_to == FindingStatus.FIXED


def test_peer_review_request_does_not_update_status(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    group = db_session.scalars(
        select(ProjectVulnerabilityGroup).where(
            ProjectVulnerabilityGroup.project_id == project.id,
            ProjectVulnerabilityGroup.dedupe_key == finding.primary_identifier,
        )
    ).one()

    result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="user-1",
        to_status=FindingStatus.FIXED,
        comment="Please review patch evidence.",
        require_peer_review=True,
    )
    db_session.flush()

    assert finding.status == FindingStatus.OPEN
    assert group.status == FindingStatus.OPEN
    assert result.request.state == FindingStatusChangeState.PENDING
    assert result.request.from_status == FindingStatus.OPEN
    assert result.request.to_status == FindingStatus.FIXED
    assert result.request.decided_at is None
    assert result.comment.status_from == FindingStatus.OPEN
    assert result.comment.status_to == FindingStatus.FIXED
    assert db_session.scalars(select(FindingStatusChangeRequest)).one() is result.request


def test_effective_peer_review_required_uses_explicit_request_flag(
    db_session: Session,
) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)

    assert (
        effective_peer_review_required(
            db_session,
            finding=finding,
            requested_peer_review=True,
        )
        is True
    )


def test_effective_peer_review_required_uses_project_setting(
    db_session: Session,
) -> None:
    project = _import_project(db_session)
    project.require_peer_review_for_status_changes = True
    finding = _openssl_finding(db_session, project)

    assert (
        effective_peer_review_required(
            db_session,
            finding=finding,
            requested_peer_review=False,
        )
        is True
    )


def test_effective_peer_review_required_uses_global_force_setting(
    db_session: Session,
) -> None:
    project = _import_project(db_session)
    settings = get_security_settings(db_session)
    settings.force_peer_review_for_status_changes = True
    finding = _openssl_finding(db_session, project)

    assert (
        effective_peer_review_required(
            db_session,
            finding=finding,
            requested_peer_review=False,
        )
        is True
    )


def test_effective_peer_review_required_returns_false_without_any_setting(
    db_session: Session,
) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)

    assert (
        effective_peer_review_required(
            db_session,
            finding=finding,
            requested_peer_review=False,
        )
        is False
    )


def test_approve_status_request_updates_finding_and_group(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    group = db_session.scalars(
        select(ProjectVulnerabilityGroup).where(
            ProjectVulnerabilityGroup.project_id == project.id,
            ProjectVulnerabilityGroup.dedupe_key == finding.primary_identifier,
        )
    ).one()
    status_result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="requester-1",
        to_status=FindingStatus.FIXED,
        comment="Please review patch evidence.",
        require_peer_review=True,
    )

    reviewed = approve_finding_status_request(
        db_session,
        finding,
        status_result.request,
        actor_principal_type="user",
        actor_principal_id="reviewer-1",
        comment="Evidence reviewed.",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    db_session.flush()

    assert reviewed is status_result.request
    assert finding.status == FindingStatus.FIXED
    assert group.status == FindingStatus.FIXED
    assert reviewed.state == FindingStatusChangeState.APPROVED
    assert reviewed.reviewer_principal_type == "user"
    assert reviewed.reviewer_principal_id == "reviewer-1"
    assert reviewed.decision_comment == "Evidence reviewed."
    assert reviewed.decided_at == datetime(2026, 5, 8, 12, 0, tzinfo=UTC)


def test_reject_status_request_leaves_finding_and_group_status(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    group = db_session.scalars(
        select(ProjectVulnerabilityGroup).where(
            ProjectVulnerabilityGroup.project_id == project.id,
            ProjectVulnerabilityGroup.dedupe_key == finding.primary_identifier,
        )
    ).one()
    status_result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="requester-1",
        to_status=FindingStatus.FIXED,
        comment="Please review patch evidence.",
        require_peer_review=True,
    )

    reviewed = reject_finding_status_request(
        db_session,
        finding,
        status_result.request,
        actor_principal_type="user",
        actor_principal_id="reviewer-1",
        comment="Patch evidence is incomplete.",
        now=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    db_session.flush()

    assert reviewed is status_result.request
    assert finding.status == FindingStatus.OPEN
    assert group.status == FindingStatus.OPEN
    assert reviewed.state == FindingStatusChangeState.REJECTED
    assert reviewed.reviewer_principal_type == "user"
    assert reviewed.reviewer_principal_id == "reviewer-1"
    assert reviewed.decision_comment == "Patch evidence is incomplete."
    assert reviewed.decided_at == datetime(2026, 5, 8, 12, 0, tzinfo=UTC)


def test_status_request_self_review_is_blocked(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    status_result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="requester-1",
        to_status=FindingStatus.FIXED,
        comment="Please review patch evidence.",
        require_peer_review=True,
    )

    with pytest.raises(ValueError, match="Requester cannot review their own status change"):
        approve_finding_status_request(
            db_session,
            finding,
            status_result.request,
            actor_principal_type="user",
            actor_principal_id="requester-1",
            comment=None,
        )


def test_status_request_review_requires_pending_state(db_session: Session) -> None:
    project = _import_project(db_session)
    finding = _openssl_finding(db_session, project)
    status_result = change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="requester-1",
        to_status=FindingStatus.FIXED,
        comment="Please review patch evidence.",
        require_peer_review=True,
    )
    approve_finding_status_request(
        db_session,
        finding,
        status_result.request,
        actor_principal_type="user",
        actor_principal_id="reviewer-1",
        comment=None,
    )

    with pytest.raises(ValueError, match="Status change request is not pending"):
        reject_finding_status_request(
            db_session,
            finding,
            status_result.request,
            actor_principal_type="user",
            actor_principal_id="reviewer-2",
            comment="Too late.",
        )
