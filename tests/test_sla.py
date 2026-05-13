import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from dionysus.models.findings import FindingStatus, RawFindingInstance, Scan, ScannerKind
from dionysus.models.inventory import AssetNode, AssetNodeType, Project


def _finding(
    *,
    severity: str = "HIGH",
    status: FindingStatus = FindingStatus.OPEN,
    first_seen_at: datetime | None = None,
) -> RawFindingInstance:
    return RawFindingInstance(
        project_id="project-1",
        scan_id="scan-1",
        scan_target_id="asset-1",
        scanner_kind=ScannerKind.TRIVY,
        scanner_finding_id="CVE-2026-0001:openssl",
        dedupe_key="trivy|asset-1|openssl|CVE-2026-0001",
        identifiers_json=["CVE-2026-0001"],
        primary_identifier="CVE-2026-0001",
        severity=severity,
        cvss_json={},
        package_name="openssl",
        package_version="3.0.0",
        fixed_version="3.0.1",
        artifact_name="registry.example.test/api:latest",
        artifact_type="container_image",
        artifact_path="usr/lib/ssl",
        first_seen_at=first_seen_at or datetime(2026, 5, 1, tzinfo=UTC),
        last_seen_at=first_seen_at or datetime(2026, 5, 1, tzinfo=UTC),
        present_in_latest_scan=True,
        status=status,
        references_json=[],
        source_json={},
    )


def test_project_has_default_severity_sla_days(db_session: Session) -> None:
    project = Project(slug="alpha", name="Alpha")
    db_session.add(project)
    db_session.flush()

    assert project.critical_sla_days == 30
    assert project.high_sla_days == 60
    assert project.medium_sla_days == 90
    assert project.low_sla_days == 180
    assert project.unknown_sla_days == 365


def test_alembic_revision_0005_chains_after_imports_findings() -> None:
    revision_path = Path("migrations/versions/0005_project_sla_fields.py")
    spec = importlib.util.spec_from_file_location("revision_0005_project_sla_fields", revision_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0005_project_sla_fields"
    assert module.down_revision == "0004_imports_findings"


def test_calculate_sla_state_returns_remaining_days_for_open_findings() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha")
    finding = _finding(
        severity="HIGH",
        first_seen_at=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
    )

    state = calculate_sla_state(
        project,
        None,
        finding,
        now=datetime(2026, 5, 11, 9, 0, tzinfo=UTC),
    )

    assert state.active is True
    assert state.remaining_days == 50
    assert state.include_in_sla_reports is True
    assert state.status == "active"


def test_calculate_sla_state_accepts_sqlite_reloaded_naive_first_seen_at(
    db_session: Session,
) -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha")
    asset = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
    )
    db_session.add_all([project, asset])
    db_session.flush()
    scan = Scan(
        project_id=project.id,
        scan_target_id=asset.id,
        scanner_kind=ScannerKind.TRIVY,
        report_kind="trivy-json",
        parser_version="1",
    )
    db_session.add(scan)
    db_session.flush()
    finding = _finding(
        severity="HIGH",
        first_seen_at=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
    )
    finding.project_id = project.id
    finding.scan_id = scan.id
    finding.scan_target_id = asset.id
    db_session.add(finding)
    db_session.commit()
    db_session.expire_all()

    reloaded_finding = db_session.get(RawFindingInstance, finding.id)
    assert reloaded_finding is not None
    assert reloaded_finding.first_seen_at.tzinfo is None

    state = calculate_sla_state(
        project,
        asset,
        reloaded_finding,
        now=datetime(2026, 5, 11, 9, 0, tzinfo=UTC),
    )

    assert state.remaining_days == 50


def test_calculate_sla_state_uses_unknown_sla_days_for_unrecognized_severity() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", unknown_sla_days=17)
    finding = _finding(
        severity="WEIRD_VENDOR_SEVERITY",
        first_seen_at=datetime(2026, 5, 1, tzinfo=UTC),
    )

    state = calculate_sla_state(
        project,
        None,
        finding,
        now=datetime(2026, 5, 6, tzinfo=UTC),
    )

    assert state.sla_days == 17
    assert state.remaining_days == 12


def test_grace_remaining_uses_project_grace_percent_when_enabled() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(
        slug="alpha",
        name="Alpha",
        grace_period_enabled=True,
        grace_period_percent=25,
    )
    finding = _finding(
        severity="critical",
        first_seen_at=datetime(2026, 5, 1, tzinfo=UTC),
    )

    state = calculate_sla_state(
        project,
        None,
        finding,
        now=datetime(2026, 5, 21, tzinfo=UTC),
    )

    assert state.remaining_days == 10
    assert state.grace_remaining_days == 17


def test_asset_grace_period_override_inherits_from_parent_folder() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(
        slug="alpha",
        name="Alpha",
        grace_period_enabled=False,
        grace_period_percent=100,
    )
    release_folder = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="release",
        path="release",
        grace_period_enabled=True,
        grace_period_percent=50,
    )
    release_asset = AssetNode(
        project=project,
        parent=release_folder,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="release/api-image",
    )
    finding = _finding(first_seen_at=datetime(2026, 5, 1, tzinfo=UTC))

    state = calculate_sla_state(
        project,
        release_asset,
        finding,
        now=datetime(2026, 5, 11, tzinfo=UTC),
    )

    assert state.remaining_days == 50
    assert state.grace_days == 30
    assert state.grace_remaining_days == 80


def test_asset_grace_period_override_can_disable_project_grace() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(
        slug="alpha",
        name="Alpha",
        grace_period_enabled=True,
        grace_period_percent=50,
    )
    non_release_folder = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="non-release",
        path="non-release",
        grace_period_enabled=False,
    )
    non_release_asset = AssetNode(
        project=project,
        parent=non_release_folder,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="non-release/api-image",
    )
    finding = _finding(first_seen_at=datetime(2026, 5, 1, tzinfo=UTC))

    state = calculate_sla_state(
        project,
        non_release_asset,
        finding,
        now=datetime(2026, 5, 11, tzinfo=UTC),
    )

    assert state.grace_days is None
    assert state.grace_remaining_days is None


def test_non_open_findings_return_inactive_not_applicable_sla_state() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha")
    finding = _finding(status=FindingStatus.FIXED)

    state = calculate_sla_state(
        project,
        None,
        finding,
        now=finding.first_seen_at + timedelta(days=10),
    )

    assert state.active is False
    assert state.remaining_days is None
    assert state.grace_remaining_days is None
    assert state.include_in_sla_reports is False
    assert state.status == "not_applicable"


def test_disabled_project_sla_tracking_returns_inactive_state() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", sla_tracking_enabled=False)
    finding = _finding()

    state = calculate_sla_state(project, None, finding, now=finding.first_seen_at)

    assert state.active is False
    assert state.remaining_days is None
    assert state.status == "tracking_disabled"


def test_disabled_project_sla_tracking_overrides_asset_tracking_opt_in() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", sla_tracking_enabled=False)
    asset = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        sla_tracking_enabled=True,
    )
    finding = _finding()

    state = calculate_sla_state(project, asset, finding, now=finding.first_seen_at)

    assert state.active is False
    assert state.remaining_days is None
    assert state.grace_remaining_days is None
    assert state.status == "tracking_disabled"


def test_disabled_asset_sla_tracking_overrides_project_tracking() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", sla_tracking_enabled=True)
    asset = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        sla_tracking_enabled=False,
    )
    finding = _finding()

    state = calculate_sla_state(project, asset, finding, now=finding.first_seen_at)

    assert state.active is False
    assert state.remaining_days is None
    assert state.status == "tracking_disabled"


def test_disabled_sla_reporting_sets_exclusion_flag() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", sla_reporting_enabled=False)
    finding = _finding()

    state = calculate_sla_state(project, None, finding, now=finding.first_seen_at)

    assert state.active is True
    assert state.include_in_sla_reports is False


def test_disabled_project_sla_reporting_overrides_asset_reporting_opt_in() -> None:
    from dionysus.findings.sla import calculate_sla_state

    project = Project(slug="alpha", name="Alpha", sla_reporting_enabled=False)
    asset = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        sla_reporting_enabled=True,
    )
    finding = _finding()

    state = calculate_sla_state(project, asset, finding, now=finding.first_seen_at)

    assert state.active is True
    assert state.include_in_sla_reports is False
