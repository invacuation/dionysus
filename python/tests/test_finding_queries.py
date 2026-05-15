from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.findings.queries import (
    FindingFilters,
    FindingSort,
    SortDirection,
    SortKey,
    get_finding_detail,
    list_findings,
)
from dionysus.findings.workflow import add_finding_comment, change_finding_status
from dionysus.imports.persistence import import_trivy_report
from dionysus.models.findings import FindingStatus, RawFindingInstance
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _project_and_target(
    session: Session,
    *,
    slug: str,
    target_name: str,
) -> tuple[Project, AssetNode]:
    project = Project(slug=slug, name=slug.title())
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name=target_name,
        path=f"images/{target_name}",
        target_ref=f"registry.example.test/dionysus/{target_name}:2026.05.07",
    )
    session.add_all([project, target])
    session.flush()
    return project, target


def _import_two_projects(session: Session) -> tuple[Project, AssetNode, Project, AssetNode]:
    alpha, alpha_target = _project_and_target(
        session,
        slug="alpha",
        target_name="api",
    )
    beta, beta_target = _project_and_target(
        session,
        slug="beta",
        target_name="worker",
    )
    import_trivy_report(
        session,
        project=alpha,
        scan_target=alpha_target,
        payload=FIXTURE.read_bytes(),
        now=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
    )
    import_trivy_report(
        session,
        project=beta,
        scan_target=beta_target,
        payload=FIXTURE.read_bytes(),
        now=datetime(2026, 5, 3, 10, 0, tzinfo=UTC),
    )
    fixed = session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == beta.id,
            RawFindingInstance.package_name == "requests",
        )
    ).one()
    fixed.status = FindingStatus.FIXED
    absent = session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == alpha.id,
            RawFindingInstance.package_name == "requests",
        )
    ).one()
    absent.present_in_latest_scan = False
    session.flush()
    return alpha, alpha_target, beta, beta_target


def _query_now() -> datetime:
    return datetime(2026, 5, 11, 9, 0, tzinfo=UTC)


def test_list_findings_returns_rows_with_project_target_group_and_sla_state(
    db_session: Session,
) -> None:
    _import_two_projects(db_session)

    rows = list_findings(db_session, now=_query_now())

    assert len(rows) == 4
    row = next(row for row in rows if row.finding.package_name == "openssl")
    assert row.project.slug in {"alpha", "beta"}
    assert row.target.node_type == AssetNodeType.SCAN_TARGET
    assert row.finding.primary_identifier == "CVE-2026-1001"
    assert row.group is not None
    assert row.group.primary_identifier == "CVE-2026-1001"
    assert row.sla_state.active is True
    assert row.sla_state.remaining_days is not None


def test_list_findings_filters_by_simple_columns_and_latest_presence(
    db_session: Session,
) -> None:
    alpha, alpha_target, beta, _beta_target = _import_two_projects(db_session)

    assert {
        row.finding.id
        for row in list_findings(
            db_session,
            filters=FindingFilters(project_id=alpha.id),
            now=_query_now(),
        )
    } == {
        finding.id
        for finding in db_session.scalars(
            select(RawFindingInstance).where(RawFindingInstance.project_id == alpha.id)
        )
    }
    assert [
        row.finding.package_name
        for row in list_findings(
            db_session,
            filters=FindingFilters(scan_target_id=alpha_target.id),
            sort=FindingSort(SortKey.PACKAGE, SortDirection.ASC),
            now=_query_now(),
        )
    ] == ["openssl", "requests"]
    assert (
        len(
            list_findings(
                db_session,
                filters=FindingFilters(scanner="trivy"),
                now=_query_now(),
            )
        )
        == 4
    )
    assert {
        row.finding.package_name
        for row in list_findings(
            db_session,
            filters=FindingFilters(severity="critical"),
            now=_query_now(),
        )
    } == {"openssl"}
    assert {
        row.finding.primary_identifier
        for row in list_findings(
            db_session,
            filters=FindingFilters(identifier="CWE-601"),
            now=_query_now(),
        )
    } == {"CVE-2026-2002"}
    assert {
        row.finding.package_name
        for row in list_findings(
            db_session,
            filters=FindingFilters(package="ssl"),
            now=_query_now(),
        )
    } == {"openssl"}
    assert {
        row.finding.status
        for row in list_findings(
            db_session,
            filters=FindingFilters(status=FindingStatus.FIXED),
            now=_query_now(),
        )
    } == {FindingStatus.FIXED}
    assert {
        row.finding.project_id
        for row in list_findings(
            db_session,
            filters=FindingFilters(present_in_latest_scan=False),
            now=_query_now(),
        )
    } == {alpha.id}
    assert {
        row.finding.project_id
        for row in list_findings(
            db_session,
            filters=FindingFilters(present_in_latest_scan=True),
            now=_query_now(),
        )
    } == {alpha.id, beta.id}


def test_list_findings_filters_by_folder_asset_descendant_scan_targets(
    db_session: Session,
) -> None:
    alpha = Project(slug="alpha", name="Alpha")
    beta = Project(slug="beta", name="Beta")
    folder = AssetNode(
        project=alpha,
        node_type=AssetNodeType.FOLDER,
        name="Images",
        path="images",
    )
    nested_folder = AssetNode(
        project=alpha,
        parent=folder,
        node_type=AssetNodeType.FOLDER,
        name="Services",
        path="images/services",
    )
    api_target = AssetNode(
        project=alpha,
        parent=folder,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api",
        path="images/api",
        target_ref="registry.example.test/dionysus/api:2026.05.07",
    )
    worker_target = AssetNode(
        project=alpha,
        parent=nested_folder,
        node_type=AssetNodeType.SCAN_TARGET,
        name="worker",
        path="images/services/worker",
        target_ref="registry.example.test/dionysus/worker:2026.05.07",
    )
    sibling_target = AssetNode(
        project=alpha,
        node_type=AssetNodeType.SCAN_TARGET,
        name="docs",
        path="docs",
        target_ref="registry.example.test/dionysus/docs:2026.05.07",
    )
    beta_target = AssetNode(
        project=beta,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api",
        path="images/api",
        target_ref="registry.example.test/dionysus/beta-api:2026.05.07",
    )
    db_session.add_all([alpha, beta])
    db_session.flush()
    for target in [api_target, worker_target, sibling_target, beta_target]:
        import_trivy_report(
            db_session,
            project=target.project,
            scan_target=target,
            payload=FIXTURE.read_bytes(),
            now=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
        )

    rows = list_findings(
        db_session,
        filters=FindingFilters(project_id=alpha.id, asset_id=folder.id),
        now=_query_now(),
    )

    assert {row.target.id for row in rows} == {api_target.id, worker_target.id}
    assert {row.project.id for row in rows} == {alpha.id}


def test_list_findings_filters_by_scan_target_asset_exactly(db_session: Session) -> None:
    alpha, alpha_target, _beta, _beta_target = _import_two_projects(db_session)

    rows = list_findings(
        db_session,
        filters=FindingFilters(asset_id=alpha_target.id),
        sort=FindingSort(SortKey.PACKAGE, SortDirection.ASC),
        now=_query_now(),
    )

    assert [row.finding.package_name for row in rows] == ["openssl", "requests"]
    assert {row.target.id for row in rows} == {alpha_target.id}
    assert {row.project.id for row in rows} == {alpha.id}


def test_list_findings_asset_filter_respects_project_scope(db_session: Session) -> None:
    _alpha, alpha_target, beta, _beta_target = _import_two_projects(db_session)

    rows = list_findings(
        db_session,
        filters=FindingFilters(project_id=beta.id, asset_id=alpha_target.id),
        now=_query_now(),
    )

    assert rows == []


def test_list_findings_open_only_excludes_non_open_findings(db_session: Session) -> None:
    _import_two_projects(db_session)

    rows = list_findings(
        db_session,
        filters=FindingFilters(open_only=True),
        now=_query_now(),
    )

    assert len(rows) == 3
    assert {row.finding.status for row in rows} == {FindingStatus.OPEN}


def test_list_findings_sorts_by_supported_keys(db_session: Session) -> None:
    _import_two_projects(db_session)

    severity_rows = list_findings(
        db_session,
        sort=FindingSort(SortKey.SEVERITY, SortDirection.DESC),
        now=_query_now(),
    )
    assert [row.finding.severity for row in severity_rows] == [
        "CRITICAL",
        "CRITICAL",
        "MEDIUM",
        "MEDIUM",
    ]

    first_asc = list_findings(
        db_session,
        sort=FindingSort(SortKey.FIRST_DETECTED, SortDirection.ASC),
        now=_query_now(),
    )
    first_desc = list_findings(
        db_session,
        sort=FindingSort(SortKey.FIRST_DETECTED, SortDirection.DESC),
        now=_query_now(),
    )
    assert first_asc[0].finding.first_seen_at <= first_asc[-1].finding.first_seen_at
    assert first_desc[0].finding.first_seen_at >= first_desc[-1].finding.first_seen_at

    last_seen_desc = list_findings(
        db_session,
        sort=FindingSort(SortKey.LAST_SEEN, SortDirection.DESC),
        now=_query_now(),
    )
    assert last_seen_desc[0].finding.last_seen_at >= last_seen_desc[-1].finding.last_seen_at

    packages = [
        row.finding.package_name
        for row in list_findings(
            db_session,
            sort=FindingSort(SortKey.PACKAGE, SortDirection.ASC),
            now=_query_now(),
        )
    ]
    assert packages == sorted(packages)

    identifiers = [
        row.finding.primary_identifier
        for row in list_findings(
            db_session,
            sort=FindingSort(SortKey.IDENTIFIER, SortDirection.ASC),
            now=_query_now(),
        )
    ]
    assert identifiers == sorted(identifiers)

    sla_remaining = [
        row.sla_state.remaining_days
        for row in list_findings(
            db_session,
            sort=FindingSort(SortKey.SLA_REMAINING, SortDirection.ASC),
            now=_query_now(),
        )
    ]
    assert sla_remaining == sorted(sla_remaining, key=lambda value: (value is None, value))


def test_list_findings_sorts_sla_remaining_descending_with_inactive_rows_last(
    db_session: Session,
) -> None:
    _import_two_projects(db_session)

    rows = list_findings(
        db_session,
        sort=FindingSort(SortKey.SLA_REMAINING, SortDirection.DESC),
        now=_query_now(),
    )

    remaining_days = [row.sla_state.remaining_days for row in rows]
    assert remaining_days[-1] is None
    active_remaining_days = [day for day in remaining_days if day is not None]
    assert remaining_days[:-1] == active_remaining_days
    assert active_remaining_days == sorted(active_remaining_days, reverse=True)
    assert rows[-1].finding.status == FindingStatus.FIXED
    assert all(row.sla_state.active for row in rows[:-1])


def test_list_findings_sorts_informational_between_unknown_and_low(
    db_session: Session,
) -> None:
    _import_two_projects(db_session)
    findings = db_session.scalars(select(RawFindingInstance).order_by(RawFindingInstance.id)).all()
    for finding, severity in zip(
        findings[:3],
        ["UNKNOWN", "INFORMATIONAL", "LOW"],
        strict=True,
    ):
        finding.severity = severity
        finding.primary_identifier = f"ORDER-{severity}"
        finding.scanner_finding_id = f"ORDER-{severity}"
        finding.identifiers_json = [f"ORDER-{severity}"]
    db_session.flush()

    descending_rows = list_findings(
        db_session,
        filters=FindingFilters(identifier="ORDER-"),
        sort=FindingSort(SortKey.SEVERITY, SortDirection.DESC),
        now=_query_now(),
    )
    assert [row.finding.severity for row in descending_rows] == [
        "LOW",
        "INFORMATIONAL",
        "UNKNOWN",
    ]

    ascending_rows = list_findings(
        db_session,
        filters=FindingFilters(identifier="ORDER-"),
        sort=FindingSort(SortKey.SEVERITY, SortDirection.ASC),
        now=_query_now(),
    )
    assert [row.finding.severity for row in ascending_rows] == [
        "UNKNOWN",
        "INFORMATIONAL",
        "LOW",
    ]


def test_get_finding_detail_loads_raw_finding_context_and_evidence(
    db_session: Session,
) -> None:
    alpha, _alpha_target, _beta, _beta_target = _import_two_projects(db_session)
    finding = db_session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == alpha.id,
            RawFindingInstance.package_name == "openssl",
        )
    ).one()

    detail = get_finding_detail(db_session, finding.id, now=_query_now())

    assert detail is not None
    assert detail.project is alpha
    assert detail.target.project_id == alpha.id
    assert detail.finding.primary_identifier == "CVE-2026-1001"
    assert detail.group is not None
    assert detail.group.primary_identifier == "CVE-2026-1001"
    assert detail.finding.identifiers_json[:2] == ["CVE-2026-1001", "CWE-787"]
    assert detail.finding.cvss_json["nvd"]["v3"]["score"] == 9.1
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1001" in (detail.finding.references_json)
    assert detail.finding.source_json["result_class"] == "os-pkgs"
    assert detail.sla_state.remaining_days == 20


def test_get_finding_detail_includes_chronological_comments_and_status_requests(
    db_session: Session,
) -> None:
    alpha, _alpha_target, _beta, _beta_target = _import_two_projects(db_session)
    finding = db_session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == alpha.id,
            RawFindingInstance.package_name == "openssl",
        )
    ).one()
    add_finding_comment(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="user-1",
        body="Initial triage note.",
    )
    change_finding_status(
        db_session,
        finding,
        actor_principal_type="user",
        actor_principal_id="user-1",
        to_status=FindingStatus.FIXED,
        comment="Patch evidence ready for review.",
        require_peer_review=True,
    )
    db_session.flush()

    detail = get_finding_detail(db_session, finding.id, now=_query_now())

    assert detail is not None
    assert [comment.body for comment in detail.comments] == [
        "Initial triage note.",
        "Patch evidence ready for review.",
    ]
    assert detail.comments[0].status_from is None
    assert detail.comments[1].status_from == FindingStatus.OPEN
    assert detail.comments[1].status_to == FindingStatus.FIXED
    assert len(detail.status_change_requests) == 1
    assert detail.status_change_requests[0].comment == "Patch evidence ready for review."
    assert detail.status_change_requests[0].state == "pending"


def test_get_finding_detail_returns_none_for_unknown_id(db_session: Session) -> None:
    _import_two_projects(db_session)

    assert (
        get_finding_detail(
            db_session,
            "00000000-0000-0000-0000-000000000000",
            now=_query_now(),
        )
        is None
    )
