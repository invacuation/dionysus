from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.findings.release_inheritance import (
    ReleaseContext,
    finding_inheritance_identity,
    latest_applicable_decision,
    record_release_status_decision,
    release_context_for_scan_target,
)
from dionysus.models.findings import (
    FindingComment,
    FindingReleaseStatusDecision,
    FindingStatus,
    FindingStatusChangeRequest,
    FindingStatusChangeState,
    RawFindingInstance,
    Scan,
    ScannerKind,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project


def _project(session: Session, *, slug: str = "alpha") -> Project:
    project = Project(slug=slug, name=slug.title())
    session.add(project)
    session.flush()
    return project


def _release_tree(
    session: Session,
    *,
    project_slug: str = "alpha",
    release_version: str | None = "40.0.2",
    version_name: str = "V40",
) -> tuple[Project, AssetNode, AssetNode, AssetNode]:
    project = _project(session, slug=project_slug)
    scope = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="releases",
        path="releases",
        metadata_json={"release_inheritance_scope": True},
    )
    metadata_json = {}
    if release_version is not None:
        metadata_json["release_version"] = release_version
    version = AssetNode(
        project=project,
        parent=scope,
        node_type=AssetNodeType.FOLDER,
        name=version_name,
        path=f"releases/{version_name}",
        metadata_json=metadata_json,
    )
    target = AssetNode(
        project=project,
        parent=version,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path=f"releases/{version_name}/images/api",
        target_ref=f"registry.example.test/api:{version_name}",
    )
    session.add_all([scope, version, target])
    session.flush()
    return project, scope, version, target


def _standalone_target(session: Session) -> tuple[Project, AssetNode]:
    project = _project(session)
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        target_ref="registry.example.test/api:latest",
    )
    session.add(target)
    session.flush()
    return project, target


def _finding(
    session: Session,
    project: Project,
    target: AssetNode,
    *,
    primary_identifier: str = "CVE-2026-0001",
    package_name: str | None = "openssl",
    scanner_kind: str = ScannerKind.TRIVY,
    report_kind: str = "trivy-image-json",
    status: str | FindingStatus = FindingStatus.ACCEPTED_RISK,
) -> RawFindingInstance:
    scan = Scan(
        project=project,
        scan_target=target,
        scanner_kind=scanner_kind,
        report_kind=report_kind,
        parser_version="1.0",
    )
    finding = RawFindingInstance(
        project=project,
        scan=scan,
        scan_target=target,
        scanner_kind=scanner_kind,
        scanner_finding_id=f"{primary_identifier}:{package_name or ''}:3.0.0",
        dedupe_key=(
            f"{target.id}|{scanner_kind}|{report_kind}|{primary_identifier}|{package_name or ''}"
        ),
        identifiers_json=[primary_identifier],
        primary_identifier=primary_identifier,
        severity="HIGH",
        package_name=package_name,
        status=status,
    )
    session.add(finding)
    session.flush()
    return finding


def _decision(
    session: Session,
    *,
    project: Project,
    scope: AssetNode,
    version: AssetNode,
    release_version: str,
    finding: RawFindingInstance,
    status: str | FindingStatus,
    scanner_kind: str = ScannerKind.TRIVY,
    report_kind: str = "trivy-image-json",
    identity: str = "CVE-2026-0001|openssl",
    decided_at: datetime | None = None,
) -> FindingReleaseStatusDecision:
    decision = FindingReleaseStatusDecision(
        project=project,
        release_scope_asset=scope,
        release_version_asset=version,
        release_version=release_version,
        scanner_kind=scanner_kind,
        report_kind=report_kind,
        finding_identity=identity,
        status=status,
        source_finding=finding,
        decided_at=decided_at or datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    session.add(decision)
    session.flush()
    return decision


def _version_asset_for_decision(
    session: Session,
    *,
    project: Project,
    scope: AssetNode,
    release_version: str,
) -> AssetNode:
    version = AssetNode(
        project=project,
        parent=scope,
        node_type=AssetNodeType.FOLDER,
        name=f"decision-{release_version}",
        path=f"{scope.path}/decision-{release_version}",
        metadata_json={"release_version": release_version},
    )
    session.add(version)
    session.flush()
    return version


def test_release_context_returns_none_for_scan_target_outside_release_scope(
    db_session: Session,
) -> None:
    _project, target = _standalone_target(db_session)

    assert release_context_for_scan_target(db_session, target) is None


def test_release_context_resolves_scope_version_and_metadata_version(
    db_session: Session,
) -> None:
    _project, scope, version, target = _release_tree(db_session)

    assert release_context_for_scan_target(db_session, target) == ReleaseContext(
        scope_asset_id=scope.id,
        scope_path="releases",
        version_asset_id=version.id,
        version_path="releases/V40",
        version="40.0.2",
    )


def test_release_context_falls_back_to_version_folder_name(db_session: Session) -> None:
    _project, _scope, _version, target = _release_tree(
        db_session,
        release_version=None,
        version_name="40.0.2",
    )

    context = release_context_for_scan_target(db_session, target)

    assert context is not None
    assert context.version == "40.0.2"


def test_release_context_falls_back_to_version_folder_name_when_metadata_version_blank(
    db_session: Session,
) -> None:
    _project, _scope, _version, target = _release_tree(
        db_session,
        release_version="   ",
        version_name="40.0.2",
    )

    context = release_context_for_scan_target(db_session, target)

    assert context is not None
    assert context.version == "40.0.2"


def test_release_context_returns_none_when_parent_is_missing(db_session: Session) -> None:
    project = _project(db_session)
    target = AssetNode(
        project=project,
        parent_id="missing-parent",
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="releases/V40/images/api",
        target_ref="registry.example.test/api:V40",
    )
    db_session.add(target)
    db_session.flush()

    assert release_context_for_scan_target(db_session, target) is None


def test_release_context_returns_none_when_scope_child_is_not_folder(
    db_session: Session,
) -> None:
    project = _project(db_session)
    scope = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="releases",
        path="releases",
        metadata_json={"release_inheritance_scope": True},
    )
    target = AssetNode(
        project=project,
        parent=scope,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="releases/api-image",
        target_ref="registry.example.test/api:V40",
    )
    db_session.add_all([scope, target])
    db_session.flush()

    assert release_context_for_scan_target(db_session, target) is None


def test_release_context_returns_none_for_malformed_metadata_on_ancestor(
    db_session: Session,
) -> None:
    project, _scope, version, target = _release_tree(db_session)
    intermediate = AssetNode(
        project=project,
        parent=version,
        node_type=AssetNodeType.FOLDER,
        name="images",
        path="releases/V40/images",
        metadata_json=["not", "an", "object"],
    )
    target.parent = intermediate
    target.path = "releases/V40/images/api"
    db_session.add(intermediate)
    db_session.flush()

    assert release_context_for_scan_target(db_session, target) is None


def test_release_context_uses_nearest_marked_scope(db_session: Session) -> None:
    project = _project(db_session)
    outer_scope = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="releases",
        path="releases",
        metadata_json={"release_inheritance_scope": True},
    )
    outer_version = AssetNode(
        project=project,
        parent=outer_scope,
        node_type=AssetNodeType.FOLDER,
        name="V40",
        path="releases/V40",
        metadata_json={"release_version": "40.0.0"},
    )
    inner_scope = AssetNode(
        project=project,
        parent=outer_version,
        node_type=AssetNodeType.FOLDER,
        name="service-releases",
        path="releases/V40/service-releases",
        metadata_json={"release_inheritance_scope": True},
    )
    inner_version = AssetNode(
        project=project,
        parent=inner_scope,
        node_type=AssetNodeType.FOLDER,
        name="V40.1",
        path="releases/V40/service-releases/V40.1",
        metadata_json={"release_version": "40.1.0"},
    )
    target = AssetNode(
        project=project,
        parent=inner_version,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="releases/V40/service-releases/V40.1/images/api",
        target_ref="registry.example.test/api:V40.1",
    )
    db_session.add_all([outer_scope, outer_version, inner_scope, inner_version, target])
    db_session.flush()

    assert release_context_for_scan_target(db_session, target) == ReleaseContext(
        scope_asset_id=inner_scope.id,
        scope_path=inner_scope.path,
        version_asset_id=inner_version.id,
        version_path=inner_version.path,
        version="40.1.0",
    )


def test_finding_inheritance_identity_normalizes_and_validates() -> None:
    assert finding_inheritance_identity(" CVE-2026-0001 ", " openssl ") == "CVE-2026-0001|openssl"
    assert finding_inheritance_identity("CVE-2026-0001", None) == "CVE-2026-0001|"
    assert finding_inheritance_identity("CVE-2026-0001", "   ") == "CVE-2026-0001|"

    with pytest.raises(ValueError):
        finding_inheritance_identity("   ", "openssl")


def test_latest_applicable_decision_uses_highest_numeric_version_at_or_before_context(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.3")
    finding = _finding(db_session, project, target)
    older = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.1",
        ),
        release_version="40.0.1",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
    )
    latest = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.3"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is latest
    assert decision is not older


def test_latest_applicable_decision_does_not_cross_scanner_kind_or_report_kind(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.3")
    finding = _finding(db_session, project, target)
    _decision(
        db_session,
        project=project,
        scope=scope,
        version=version,
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
        scanner_kind="other-scanner",
    )
    _decision(
        db_session,
        project=project,
        scope=scope,
        version=version,
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
        report_kind="other-report",
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.3"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is None


def test_latest_applicable_decision_returns_open_decision_as_latest_barrier(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.3")
    finding = _finding(db_session, project, target)
    _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.1",
        ),
        release_version="40.0.1",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
    )
    open_decision = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.OPEN,
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.3"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is open_decision


def test_latest_applicable_decision_pads_numeric_version_tuples(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.1")
    finding = _finding(db_session, project, target)
    padded = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0",
        ),
        release_version="40.0",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.1"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is padded


def test_latest_applicable_decision_treats_equivalent_padded_versions_as_ties(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(
        db_session,
        release_version="1.0",
        version_name="V1",
    )
    finding = _finding(db_session, project, target)
    longer_raw_tuple = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="1.0.0",
        ),
        release_version="1.0.0",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
        decided_at=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    shorter_raw_tuple_later_decision = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="1.0",
        ),
        release_version="1.0",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
        decided_at=datetime(2026, 5, 8, 13, 0, tzinfo=UTC),
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "1.0"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is shorter_raw_tuple_later_decision
    assert decision is not longer_raw_tuple


def test_latest_applicable_decision_only_matches_exact_non_numeric_versions(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="V40.0.3")
    finding = _finding(db_session, project, target)
    _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="V40.0.2",
        ),
        release_version="V40.0.2",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
    )
    exact = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="V40.0.3",
        ),
        release_version="V40.0.3",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "V40.0.3"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is exact


def test_latest_applicable_decision_isolates_project_scope_and_identity(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.3")
    finding = _finding(db_session, project, target)
    expected = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
    )
    _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.3",
        ),
        release_version="40.0.3",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
        identity="CVE-2026-9999|openssl",
    )

    other_project, other_scope, other_version, other_target = _release_tree(
        db_session,
        project_slug="other",
        release_version="40.0.3",
        version_name="OtherV40",
    )
    other_finding = _finding(db_session, other_project, other_target)
    _decision(
        db_session,
        project=other_project,
        scope=other_scope,
        version=other_version,
        release_version="40.0.3",
        finding=other_finding,
        status=FindingStatus.FIXED,
    )

    other_scope = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="other-releases",
        path="other-releases",
        metadata_json={"release_inheritance_scope": True},
    )
    other_scope_version = AssetNode(
        project=project,
        parent=other_scope,
        node_type=AssetNodeType.FOLDER,
        name="V40",
        path="other-releases/V40",
        metadata_json={"release_version": "40.0.3"},
    )
    db_session.add_all([other_scope, other_scope_version])
    db_session.flush()
    _decision(
        db_session,
        project=project,
        scope=other_scope,
        version=other_scope_version,
        release_version="40.0.3",
        finding=finding,
        status=FindingStatus.FIXED,
    )

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.3"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is expected


def test_latest_applicable_decision_breaks_same_version_ties_by_decision_fields(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session, release_version="40.0.2")
    finding = _finding(db_session, project, target)
    same_created_at = datetime(2026, 5, 8, 11, 0, tzinfo=UTC)
    earlier_decided = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.ACCEPTED_RISK,
        decided_at=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
    )
    later_decided = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2-alt",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.FALSE_POSITIVE,
        decided_at=datetime(2026, 5, 8, 13, 0, tzinfo=UTC),
    )
    earlier_decided.created_at = same_created_at
    later_decided.created_at = same_created_at
    db_session.flush()

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.2"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is later_decided

    same_decided_at = datetime(2026, 5, 8, 14, 0, tzinfo=UTC)
    older_created = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2-created-old",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.OPEN,
        decided_at=same_decided_at,
    )
    newer_created = _decision(
        db_session,
        project=project,
        scope=scope,
        version=_version_asset_for_decision(
            db_session,
            project=project,
            scope=scope,
            release_version="40.0.2-created-new",
        ),
        release_version="40.0.2",
        finding=finding,
        status=FindingStatus.FIXED,
        decided_at=same_decided_at,
    )
    older_created.created_at = datetime(2026, 5, 8, 15, 0, tzinfo=UTC)
    newer_created.created_at = datetime(2026, 5, 8, 16, 0, tzinfo=UTC)
    db_session.flush()

    decision = latest_applicable_decision(
        db_session,
        project_id=project.id,
        context=ReleaseContext(scope.id, scope.path, version.id, version.path, "40.0.2"),
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-image-json",
        finding_identity="CVE-2026-0001|openssl",
    )

    assert decision is newer_created


def test_record_release_status_decision_returns_none_outside_release_scope(
    db_session: Session,
) -> None:
    project, target = _standalone_target(db_session)
    finding = _finding(db_session, project, target)

    assert (
        record_release_status_decision(
            db_session,
            finding=finding,
            status=FindingStatus.ACCEPTED_RISK,
        )
        is None
    )


def test_record_release_status_decision_creates_then_updates_same_release_identity(
    db_session: Session,
) -> None:
    project, scope, version, target = _release_tree(db_session)
    first_finding = _finding(db_session, project, target, status=FindingStatus.ACCEPTED_RISK)
    comment = FindingComment(
        project=project,
        finding=first_finding,
        author_principal_type="user",
        author_principal_id="user-1",
        body="Accepting for this release line.",
        is_system=False,
        status_from=FindingStatus.OPEN,
        status_to=FindingStatus.ACCEPTED_RISK,
    )
    request = FindingStatusChangeRequest(
        project=project,
        finding=first_finding,
        requester_principal_type="user",
        requester_principal_id="user-1",
        reviewer_principal_type="user",
        reviewer_principal_id="user-2",
        from_status=FindingStatus.OPEN,
        to_status=FindingStatus.ACCEPTED_RISK,
        state=FindingStatusChangeState.APPROVED,
        comment="Request release-line acceptance.",
        decision_comment="Approved for release scope.",
        decided_at=datetime(2026, 5, 8, 11, 30, tzinfo=UTC),
    )
    db_session.add_all([comment, request])
    db_session.flush()
    first_decided_at = datetime(2026, 5, 8, 12, 0, tzinfo=UTC)

    created = record_release_status_decision(
        db_session,
        finding=first_finding,
        status=FindingStatus.ACCEPTED_RISK,
        comment=comment,
        request=request,
        decided_at=first_decided_at,
    )

    assert created is not None
    assert created.project is project
    assert created.release_scope_asset is scope
    assert created.release_version_asset is version
    assert created.release_version == "40.0.2"
    assert created.scanner_kind == ScannerKind.TRIVY
    assert created.report_kind == "trivy-image-json"
    assert created.finding_identity == "CVE-2026-0001|openssl"
    assert created.status == FindingStatus.ACCEPTED_RISK
    assert created.source_finding is first_finding
    assert created.source_comment is comment
    assert created.source_request is request
    assert created.decided_at == first_decided_at

    second_finding = _finding(
        db_session,
        project,
        target,
        package_name=" openssl ",
        status=FindingStatus.FALSE_POSITIVE,
    )
    second_decided_at = first_decided_at + timedelta(hours=1)

    updated = record_release_status_decision(
        db_session,
        finding=second_finding,
        status=FindingStatus.FALSE_POSITIVE,
        decided_at=second_decided_at,
    )

    assert updated is created
    assert updated.status == FindingStatus.FALSE_POSITIVE
    assert updated.source_finding is second_finding
    assert updated.decided_at == second_decided_at
    assert db_session.scalars(select(FindingReleaseStatusDecision)).all() == [created]
