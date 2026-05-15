import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import DateTime, UniqueConstraint, create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from dionysus.models import (
    FindingComment as ExportedFindingComment,
)
from dionysus.models import (
    FindingStatus as ExportedFindingStatus,
)
from dionysus.models import (
    FindingStatusChangeRequest as ExportedFindingStatusChangeRequest,
)
from dionysus.models import (
    ImportAttempt as ExportedImportAttempt,
)
from dionysus.models import (
    ImportStatus as ExportedImportStatus,
)
from dionysus.models import (
    ProjectVulnerabilityGroup as ExportedProjectVulnerabilityGroup,
)
from dionysus.models import (
    RawFindingInstance as ExportedRawFindingInstance,
)
from dionysus.models import (
    Scan as ExportedScan,
)
from dionysus.models import (
    ScannerKind as ExportedScannerKind,
)
from dionysus.models.base import Base
from dionysus.models.findings import (
    FindingComment,
    FindingReleaseStatusDecision,
    FindingStatus,
    FindingStatusChangeRequest,
    FindingStatusChangeState,
    ImportAttempt,
    ImportStatus,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
    Scan,
    ScannerKind,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _project_and_target(session: Session) -> tuple[Project, AssetNode]:
    project = Project(slug="alpha", name="Alpha")
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        target_ref="registry.example.test/api:latest",
    )
    session.add_all([project, target])
    session.flush()
    return project, target


def test_finding_models_create_expected_tables() -> None:
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(engine)

    table_names = set(inspect(engine).get_table_names())
    assert {
        "import_attempts",
        "scans",
        "raw_finding_instances",
        "project_vulnerability_groups",
        "finding_comments",
        "finding_status_change_requests",
        "finding_release_status_decisions",
    }.issubset(table_names)


def test_finding_models_include_required_enum_values() -> None:
    assert {status.value for status in ImportStatus} == {"pending", "success", "failed"}
    assert {status.value for status in FindingStatus} == {
        "open",
        "accepted_risk",
        "false_positive",
        "mitigated",
        "suppressed",
        "fixed",
    }
    assert {kind.value for kind in ScannerKind} == {"trivy"}
    assert {state.value for state in FindingStatusChangeState} == {
        "pending",
        "applied",
        "approved",
        "rejected",
        "cancelled",
    }


def test_finding_models_are_exported_from_models_package() -> None:
    from dionysus import models as exported_models

    assert ExportedImportStatus is ImportStatus
    assert ExportedFindingStatus is FindingStatus
    assert ExportedScannerKind is ScannerKind
    assert ExportedImportAttempt is ImportAttempt
    assert ExportedScan is Scan
    assert ExportedRawFindingInstance is RawFindingInstance
    assert ExportedProjectVulnerabilityGroup is ProjectVulnerabilityGroup
    assert ExportedFindingComment is FindingComment
    assert ExportedFindingStatusChangeRequest is FindingStatusChangeRequest
    assert exported_models.FindingReleaseStatusDecision is FindingReleaseStatusDecision


def test_finding_models_include_timestamp_mixin_columns() -> None:
    from dionysus.models.findings import FindingReleaseStatusDecision

    for model in (
        ImportAttempt,
        Scan,
        RawFindingInstance,
        ProjectVulnerabilityGroup,
        FindingComment,
        FindingStatusChangeRequest,
        FindingReleaseStatusDecision,
    ):
        created_at_type = model.__table__.c.created_at.type
        updated_at_type = model.__table__.c.updated_at.type

        assert isinstance(created_at_type, DateTime)
        assert isinstance(updated_at_type, DateTime)
        assert created_at_type.timezone is True
        assert updated_at_type.timezone is True


def test_import_attempt_stores_metadata_and_safe_status_details() -> None:
    with _session() as session:
        project, target = _project_and_target(session)
        attempt = ImportAttempt(
            project=project,
            asset_node=target,
            uploader_principal_type="user",
            uploader_principal_id="user-1",
            status=ImportStatus.FAILED,
            parser_name="trivy-image-json",
            sanitized_message="invalid JSON report",
            correlation_id="corr-123",
            metadata_json={"filename": "trivy.json", "content_type": "application/json"},
        )
        session.add(attempt)
        session.flush()

        persisted = session.get(ImportAttempt, attempt.id)
        assert persisted is not None
        assert persisted.project is project
        assert persisted.asset_node is target
        assert persisted.uploader_principal_type == "user"
        assert persisted.uploader_principal_id == "user-1"
        assert persisted.status == ImportStatus.FAILED
        assert persisted.parser_name == "trivy-image-json"
        assert persisted.sanitized_message == "invalid JSON report"
        assert persisted.correlation_id == "corr-123"
        assert persisted.metadata_json == {
            "filename": "trivy.json",
            "content_type": "application/json",
        }


def test_scan_binds_project_target_and_report_metadata() -> None:
    started_at = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    finished_at = datetime(2026, 5, 7, 12, 5, tzinfo=UTC)
    with _session() as session:
        project, target = _project_and_target(session)
        scan = Scan(
            project=project,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
            scan_started_at=started_at,
            scan_finished_at=finished_at,
            metadata_json={"artifact_name": "registry.example.test/api:latest"},
        )
        session.add(scan)
        session.flush()

        persisted = session.get(Scan, scan.id)
        assert persisted is not None
        assert persisted.project is project
        assert persisted.scan_target is target
        assert persisted.scanner_kind == ScannerKind.TRIVY
        assert persisted.report_kind == "trivy-image-json"
        assert persisted.parser_version == "1.0"
        assert persisted.scan_started_at == started_at
        assert persisted.scan_finished_at == finished_at
        assert persisted.metadata_json == {"artifact_name": "registry.example.test/api:latest"}


def test_raw_finding_instance_stores_scanner_identity_and_finding_details() -> None:
    first_seen_at = datetime(2026, 5, 7, 12, 1, tzinfo=UTC)
    last_seen_at = datetime(2026, 5, 7, 12, 2, tzinfo=UTC)
    with _session() as session:
        project, target = _project_and_target(session)
        scan = Scan(
            project=project,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
        )
        raw_finding = RawFindingInstance(
            project=project,
            scan=scan,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            scanner_finding_id="CVE-2026-0001:openssl:3.0.0",
            dedupe_key="trivy|images/api|openssl|3.0.0|CVE-2026-0001",
            identifiers_json=["CVE-2026-0001", "GHSA-abcd"],
            primary_identifier="CVE-2026-0001",
            severity="HIGH",
            cvss_json={"nvd": {"v3": 8.1}},
            package_name="openssl",
            package_version="3.0.0",
            fixed_version="3.0.1",
            artifact_name="registry.example.test/api:latest",
            artifact_type="container_image",
            artifact_path="usr/lib/ssl",
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            present_in_latest_scan=True,
            status=FindingStatus.OPEN,
            references_json=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
            source_json={"target": "usr/lib/ssl", "class": "os-pkgs", "type": "debian"},
        )
        session.add(raw_finding)
        session.flush()

        persisted = session.scalars(select(RawFindingInstance)).one()
        assert persisted.project is project
        assert persisted.scan is scan
        assert persisted.scan_target is target
        assert persisted.scanner_kind == ScannerKind.TRIVY
        assert persisted.scanner_finding_id == "CVE-2026-0001:openssl:3.0.0"
        assert persisted.dedupe_key == "trivy|images/api|openssl|3.0.0|CVE-2026-0001"
        assert persisted.identifiers_json == ["CVE-2026-0001", "GHSA-abcd"]
        assert persisted.primary_identifier == "CVE-2026-0001"
        assert persisted.severity == "HIGH"
        assert persisted.cvss_json == {"nvd": {"v3": 8.1}}
        assert persisted.package_name == "openssl"
        assert persisted.package_version == "3.0.0"
        assert persisted.fixed_version == "3.0.1"
        assert persisted.artifact_name == "registry.example.test/api:latest"
        assert persisted.artifact_type == "container_image"
        assert persisted.artifact_path == "usr/lib/ssl"
        assert persisted.first_seen_at == first_seen_at
        assert persisted.last_seen_at == last_seen_at
        assert persisted.present_in_latest_scan is True
        assert persisted.status == FindingStatus.OPEN
        assert persisted.references_json == ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"]
        assert persisted.source_json == {
            "target": "usr/lib/ssl",
            "class": "os-pkgs",
            "type": "debian",
        }


def test_project_vulnerability_group_stores_grouping_fields() -> None:
    first_detected_at = datetime(2026, 5, 7, 12, 1, tzinfo=UTC)
    with _session() as session:
        project, _target = _project_and_target(session)
        group = ProjectVulnerabilityGroup(
            project=project,
            primary_identifier="CVE-2026-0001",
            additional_identifiers_json=["GHSA-abcd"],
            first_detected_at=first_detected_at,
            severity="HIGH",
            status=FindingStatus.OPEN,
            dedupe_key="CVE-2026-0001",
        )
        session.add(group)
        session.flush()

        persisted = session.scalars(select(ProjectVulnerabilityGroup)).one()
        assert persisted.project is project
        assert persisted.primary_identifier == "CVE-2026-0001"
        assert persisted.additional_identifiers_json == ["GHSA-abcd"]
        assert persisted.first_detected_at == first_detected_at
        assert persisted.severity == "HIGH"
        assert persisted.status == FindingStatus.OPEN
        assert persisted.dedupe_key == "CVE-2026-0001"


def test_finding_comment_stores_author_and_status_transition() -> None:
    with _session() as session:
        project, target = _project_and_target(session)
        scan = Scan(
            project=project,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
        )
        finding = RawFindingInstance(
            project=project,
            scan=scan,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            scanner_finding_id="CVE-2026-0001:openssl:3.0.0",
            dedupe_key="trivy|images/api|openssl|3.0.0|CVE-2026-0001",
            identifiers_json=["CVE-2026-0001"],
            primary_identifier="CVE-2026-0001",
            severity="HIGH",
            status=FindingStatus.OPEN,
        )
        comment = FindingComment(
            project=project,
            finding=finding,
            author_principal_type="user",
            author_principal_id="user-1",
            body="Marking this fixed after patch rollout.",
            is_system=False,
            status_from=FindingStatus.OPEN,
            status_to=FindingStatus.FIXED,
        )
        session.add(comment)
        session.flush()

        persisted = session.scalars(select(FindingComment)).one()
        assert persisted.project is project
        assert persisted.finding is finding
        assert persisted.author_principal_type == "user"
        assert persisted.author_principal_id == "user-1"
        assert persisted.body == "Marking this fixed after patch rollout."
        assert persisted.is_system is False
        assert persisted.status_from == FindingStatus.OPEN
        assert persisted.status_to == FindingStatus.FIXED


def test_finding_status_change_request_stores_workflow_fields() -> None:
    decided_at = datetime(2026, 5, 8, 9, 15, tzinfo=UTC)
    with _session() as session:
        project, target = _project_and_target(session)
        scan = Scan(
            project=project,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
        )
        finding = RawFindingInstance(
            project=project,
            scan=scan,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            scanner_finding_id="CVE-2026-0001:openssl:3.0.0",
            dedupe_key="trivy|images/api|openssl|3.0.0|CVE-2026-0001",
            identifiers_json=["CVE-2026-0001"],
            primary_identifier="CVE-2026-0001",
            severity="HIGH",
            status=FindingStatus.OPEN,
        )
        request = FindingStatusChangeRequest(
            project=project,
            finding=finding,
            requester_principal_type="user",
            requester_principal_id="user-1",
            reviewer_principal_type="user",
            reviewer_principal_id="user-2",
            from_status=FindingStatus.OPEN,
            to_status=FindingStatus.FIXED,
            state=FindingStatusChangeState.APPROVED,
            comment="Patch has been deployed.",
            decision_comment="Approved after validation.",
            decided_at=decided_at,
        )
        session.add(request)
        session.flush()

        persisted = session.scalars(select(FindingStatusChangeRequest)).one()
        assert persisted.project is project
        assert persisted.finding is finding
        assert persisted.requester_principal_type == "user"
        assert persisted.requester_principal_id == "user-1"
        assert persisted.reviewer_principal_type == "user"
        assert persisted.reviewer_principal_id == "user-2"
        assert persisted.from_status == FindingStatus.OPEN
        assert persisted.to_status == FindingStatus.FIXED
        assert persisted.state == FindingStatusChangeState.APPROVED
        assert persisted.comment == "Patch has been deployed."
        assert persisted.decision_comment == "Approved after validation."
        assert persisted.decided_at == decided_at


def test_finding_release_status_decision_model_persists() -> None:
    from dionysus.models.findings import FindingReleaseStatusDecision

    decided_at = datetime(2026, 5, 8, 10, 30, tzinfo=UTC)
    with _session() as session:
        project = Project(slug="alpha", name="Alpha")
        release_scope = AssetNode(
            project=project,
            node_type=AssetNodeType.FOLDER,
            name="releases",
            path="releases",
        )
        release_version = AssetNode(
            project=project,
            parent=release_scope,
            node_type=AssetNodeType.FOLDER,
            name="2026.05",
            path="releases/2026.05",
        )
        scan_target = AssetNode(
            project=project,
            parent=release_version,
            node_type=AssetNodeType.SCAN_TARGET,
            name="api-image",
            path="releases/2026.05/images/api",
            target_ref="registry.example.test/api:2026.05",
        )
        scan = Scan(
            project=project,
            scan_target=scan_target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
        )
        finding = RawFindingInstance(
            project=project,
            scan=scan,
            scan_target=scan_target,
            scanner_kind=ScannerKind.TRIVY,
            scanner_finding_id="CVE-2026-0001:openssl:3.0.0",
            dedupe_key="trivy|images/api|openssl|3.0.0|CVE-2026-0001",
            identifiers_json=["CVE-2026-0001"],
            primary_identifier="CVE-2026-0001",
            severity="HIGH",
            status=FindingStatus.OPEN,
        )
        comment = FindingComment(
            project=project,
            finding=finding,
            author_principal_type="user",
            author_principal_id="user-1",
            body="Accepting for this release line.",
            is_system=False,
            status_from=FindingStatus.OPEN,
            status_to=FindingStatus.ACCEPTED_RISK,
        )
        request = FindingStatusChangeRequest(
            project=project,
            finding=finding,
            requester_principal_type="user",
            requester_principal_id="user-1",
            reviewer_principal_type="user",
            reviewer_principal_id="user-2",
            from_status=FindingStatus.OPEN,
            to_status=FindingStatus.ACCEPTED_RISK,
            state=FindingStatusChangeState.APPROVED,
            comment="Request release-line acceptance.",
            decision_comment="Approved for release scope.",
            decided_at=decided_at,
        )
        decision = FindingReleaseStatusDecision(
            project=project,
            release_scope_asset=release_scope,
            release_version_asset=release_version,
            release_version="2026.05",
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            finding_identity="CVE-2026-0001|openssl",
            status=FindingStatus.ACCEPTED_RISK,
            source_finding=finding,
            source_comment=comment,
            source_request=request,
            decided_at=decided_at,
        )
        session.add(decision)
        session.flush()

        persisted = session.scalars(select(FindingReleaseStatusDecision)).one()
        assert persisted.project is project
        assert persisted.release_scope_asset is release_scope
        assert persisted.release_version_asset is release_version
        assert persisted.release_version == "2026.05"
        assert persisted.scanner_kind == ScannerKind.TRIVY
        assert persisted.report_kind == "trivy-image-json"
        assert persisted.finding_identity == "CVE-2026-0001|openssl"
        assert persisted.status == FindingStatus.ACCEPTED_RISK
        assert persisted.source_finding is finding
        assert persisted.source_comment is comment
        assert persisted.source_request is request
        assert persisted.decided_at == decided_at


def test_unique_constraints_prevent_duplicate_raw_and_group_dedupe_keys() -> None:
    with _session() as session:
        project, target = _project_and_target(session)
        scan = Scan(
            project=project,
            scan_target=target,
            scanner_kind=ScannerKind.TRIVY,
            report_kind="trivy-image-json",
            parser_version="1.0",
        )
        session.add(scan)
        session.flush()

        base_raw_kwargs = {
            "project": project,
            "scan": scan,
            "scan_target": target,
            "scanner_kind": ScannerKind.TRIVY,
            "scanner_finding_id": "CVE-2026-0001:openssl:3.0.0",
            "dedupe_key": "trivy|images/api|openssl|3.0.0|CVE-2026-0001",
            "identifiers_json": ["CVE-2026-0001"],
            "primary_identifier": "CVE-2026-0001",
            "severity": "HIGH",
            "status": FindingStatus.OPEN,
        }
        session.add_all(
            [
                RawFindingInstance(**base_raw_kwargs),
                RawFindingInstance(**base_raw_kwargs),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()

    with _session() as session:
        project, _target = _project_and_target(session)
        session.add_all(
            [
                ProjectVulnerabilityGroup(
                    project=project,
                    primary_identifier="CVE-2026-0001",
                    severity="HIGH",
                    status=FindingStatus.OPEN,
                    dedupe_key="CVE-2026-0001",
                ),
                ProjectVulnerabilityGroup(
                    project=project,
                    primary_identifier="CVE-2026-0001",
                    severity="HIGH",
                    status=FindingStatus.OPEN,
                    dedupe_key="CVE-2026-0001",
                ),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()


def test_finding_unique_constraint_names_match_migration() -> None:
    raw_unique_names = {
        constraint.name
        for constraint in RawFindingInstance.__mapper__.local_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    group_unique_names = {
        constraint.name
        for constraint in ProjectVulnerabilityGroup.__mapper__.local_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    release_decision_unique_names = {
        constraint.name
        for constraint in FindingReleaseStatusDecision.__mapper__.local_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert "uq_raw_finding_instances_scan_target_dedupe_key" in raw_unique_names
    assert "uq_project_vulnerability_groups_project_dedupe_key" in group_unique_names
    assert "uq_finding_release_status_decisions_release_identity" in release_decision_unique_names


def test_imports_findings_migration_revision_chain_is_stable() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0004_imports_findings.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0004_imports_findings", migration_path)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0004_imports_findings"
    assert migration.down_revision == "0003_project_asset_inventory"


def test_finding_workflow_migration_revision_chain_is_stable() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / ("0007_finding_workflow.py")
    )
    spec = importlib.util.spec_from_file_location("migration_0007_finding_workflow", migration_path)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0007_finding_workflow"
    assert migration.down_revision == "0006_bootstrap_locks"


def test_release_status_decisions_migration_revision_chain_is_stable() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0014_release_status_decisions.py"
    )
    spec = importlib.util.spec_from_file_location(
        "migration_0014_release_status_decisions",
        migration_path,
    )
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0014_release_status_decisions"
    assert migration.down_revision == "0013_asset_grace_period_overrides"


def test_finding_workflow_migration_creates_and_drops_tables(monkeypatch, tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'finding_workflow.db'}"
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    project_root = Path(__file__).parents[1]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))

    command.upgrade(config, "0007_finding_workflow")

    engine = create_engine(database_url)
    try:
        table_names = set(inspect(engine).get_table_names())
        assert "finding_comments" in table_names
        assert "finding_status_change_requests" in table_names

        command.downgrade(config, "0006_bootstrap_locks")

        table_names = set(inspect(engine).get_table_names())
        assert "finding_comments" not in table_names
        assert "finding_status_change_requests" not in table_names
    finally:
        engine.dispose()


def test_release_status_decisions_migration_creates_and_drops_table(
    monkeypatch,
    tmp_path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'release_status_decisions.db'}"
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    project_root = Path(__file__).parents[1]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))

    command.upgrade(config, "0014_release_status_decisions")

    engine = create_engine(database_url)
    try:
        table_names = set(inspect(engine).get_table_names())
        assert "finding_release_status_decisions" in table_names

        index_names = {
            index["name"]
            for index in inspect(engine).get_indexes("finding_release_status_decisions")
        }
        assert "ix_finding_release_status_decisions_scope_identity" in index_names
        assert "ix_finding_release_status_decisions_project_version" in index_names

        command.downgrade(config, "0013_asset_grace_period_overrides")

        table_names = set(inspect(engine).get_table_names())
        assert "finding_release_status_decisions" not in table_names
    finally:
        engine.dispose()


def test_imports_findings_migration_creates_and_drops_tables(monkeypatch, tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'findings.db'}"
    monkeypatch.setenv("DIONYSUS_DATABASE_URL", database_url)
    project_root = Path(__file__).parents[1]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))

    command.upgrade(config, "0004_imports_findings")

    engine = create_engine(database_url)
    try:
        table_names = set(inspect(engine).get_table_names())
        assert {
            "import_attempts",
            "scans",
            "raw_finding_instances",
            "project_vulnerability_groups",
        }.issubset(table_names)

        command.downgrade(config, "0003_project_asset_inventory")

        table_names = set(inspect(engine).get_table_names())
        assert "import_attempts" not in table_names
        assert "scans" not in table_names
        assert "raw_finding_instances" not in table_names
        assert "project_vulnerability_groups" not in table_names
    finally:
        engine.dispose()
