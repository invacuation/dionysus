from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from dionysus.imports.parsers import ParsedFinding, ParsedReport, ParserError
from dionysus.imports.persistence import ImportFailure, import_trivy_report, persist_parsed_report
from dionysus.models.findings import (
    ImportAttempt,
    ImportStatus,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
    Scan,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _project_and_target(session: Session) -> tuple[Project, AssetNode]:
    project = Project(slug="alpha", name="Alpha")
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="api-image",
        path="images/api",
        target_ref="registry.example.test/dionysus/api:2026.05.07",
    )
    session.add_all([project, target])
    session.flush()
    return project, target


def _successful_import(
    session: Session,
    *,
    project: Project,
    target: AssetNode,
    now: datetime,
):
    return import_trivy_report(
        session,
        project=project,
        scan_target=target,
        payload=FIXTURE.read_bytes(),
        now=now,
        uploader_principal_type="user",
        uploader_principal_id="user-1",
        correlation_id="corr-123",
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _parsed_report() -> ParsedReport:
    return ParsedReport(
        scanner="trivy",
        report_kind="trivy-image-json",
        parser_version="1.0",
        target="registry.example.test/dionysus/api:2026.05.07",
        findings=[
            ParsedFinding(
                scanner="trivy",
                scanner_finding_id="CVE-2026-1001",
                primary_identifier="CVE-2026-1001",
                identifiers=["CVE-2026-1001"],
                severity="HIGH",
                dedupe_key="trivy|CVE-2026-1001|pkg:openssl",
            )
        ],
    )


def _assert_no_successful_import_artifacts(session: Session) -> None:
    assert (
        session.scalars(
            select(ImportAttempt).where(ImportAttempt.status == ImportStatus.SUCCESS)
        ).all()
        == []
    )
    assert session.scalars(select(Scan)).all() == []
    assert session.scalars(select(RawFindingInstance)).all() == []
    assert session.scalars(select(ProjectVulnerabilityGroup)).all() == []


def test_successful_import_creates_attempt_scan_raw_findings_and_groups(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    now = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)

    result = _successful_import(db_session, project=project, target=target, now=now)

    attempts = db_session.scalars(select(ImportAttempt)).all()
    scans = db_session.scalars(select(Scan)).all()
    raw_findings = db_session.scalars(select(RawFindingInstance)).all()
    groups = db_session.scalars(select(ProjectVulnerabilityGroup)).all()

    assert result.attempt.status == ImportStatus.SUCCESS
    assert result.scan in scans
    assert result.raw_findings == raw_findings
    assert result.groups == groups
    assert len(attempts) == 1
    assert len(scans) == 1
    assert len(raw_findings) == 2
    assert len(groups) == 2
    assert attempts[0].project is project
    assert attempts[0].asset_node is target
    assert attempts[0].metadata_json["raw_report_retained"] is False
    assert scans[0].project is project
    assert scans[0].scan_target is target
    assert {finding.primary_identifier for finding in raw_findings} == {
        "CVE-2026-1001",
        "CVE-2026-2002",
    }
    assert {group.primary_identifier for group in groups} == {
        "CVE-2026-1001",
        "CVE-2026-2002",
    }


def test_trivy_import_does_not_duplicate_existing_nvd_references(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    now = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)

    result = _successful_import(db_session, project=project, target=target, now=now)

    os_finding = next(
        finding for finding in result.raw_findings if finding.primary_identifier == "CVE-2026-1001"
    )
    assert os_finding.references_json.count("https://nvd.nist.gov/vuln/detail/CVE-2026-1001") == 1


def test_import_reuses_project_group_for_repeated_primary_identifier_in_same_report(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    now = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    parsed_report = ParsedReport(
        scanner="trivy",
        report_kind="trivy-image-json",
        parser_version="1.0",
        target="registry.example.test/dionysus/api:2026.05.07",
        findings=[
            ParsedFinding(
                scanner="trivy",
                scanner_finding_id="CVE-2026-9001",
                primary_identifier="CVE-2026-9001",
                identifiers=["CVE-2026-9001", "GHSA-aaaa-bbbb-cccc"],
                additional_identifiers=["GHSA-aaaa-bbbb-cccc"],
                severity="LOW",
                package_name="openssl",
                dedupe_key="trivy|CVE-2026-9001|pkg:openssl",
            ),
            ParsedFinding(
                scanner="trivy",
                scanner_finding_id="CVE-2026-9001",
                primary_identifier="CVE-2026-9001",
                identifiers=["CVE-2026-9001", "GHSA-dddd-eeee-ffff"],
                additional_identifiers=["GHSA-dddd-eeee-ffff"],
                severity="CRITICAL",
                package_name="libssl",
                dedupe_key="trivy|CVE-2026-9001|pkg:libssl",
            ),
        ],
    )

    result = persist_parsed_report(
        db_session,
        project=project,
        scan_target=target,
        parsed_report=parsed_report,
        now=now,
    )

    raw_findings = db_session.scalars(select(RawFindingInstance)).all()
    groups = db_session.scalars(select(ProjectVulnerabilityGroup)).all()

    assert len(raw_findings) == 2
    assert {finding.dedupe_key for finding in raw_findings} == {
        "trivy|CVE-2026-9001|pkg:openssl",
        "trivy|CVE-2026-9001|pkg:libssl",
    }
    assert len(groups) == 1
    assert groups[0].primary_identifier == "CVE-2026-9001"
    assert groups[0].severity == "CRITICAL"
    assert groups[0].additional_identifiers_json == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    ]
    assert result.raw_findings == raw_findings
    assert result.groups == groups


def test_import_enriches_cve_finding_references_before_persistence(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    parsed_report = _parsed_report()

    result = persist_parsed_report(
        db_session,
        project=project,
        scan_target=target,
        parsed_report=parsed_report,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )

    assert result.raw_findings[0].references_json == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001"
    ]


def test_import_does_not_duplicate_existing_nvd_reference(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    parsed_report = ParsedReport(
        scanner="trivy",
        report_kind="trivy-image-json",
        parser_version="1.0",
        target="registry.example.test/dionysus/api:2026.05.07",
        findings=[
            ParsedFinding(
                scanner="trivy",
                scanner_finding_id="cve-2026-1001",
                primary_identifier="cve-2026-1001",
                identifiers=["cve-2026-1001"],
                severity="HIGH",
                dedupe_key="trivy|cve-2026-1001|pkg:openssl",
                references=["https://nvd.nist.gov/vuln/detail/cve-2026-1001"],
            )
        ],
    )

    result = persist_parsed_report(
        db_session,
        project=project,
        scan_target=target,
        parsed_report=parsed_report,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )

    assert result.raw_findings[0].references_json == [
        "https://nvd.nist.gov/vuln/detail/cve-2026-1001"
    ]


def test_first_detection_is_import_time_and_preserved_on_repeated_imports(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    first_import_at = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    second_import_at = first_import_at + timedelta(hours=2)

    first = _successful_import(db_session, project=project, target=target, now=first_import_at)
    first_seen_by_key = {
        finding.dedupe_key: finding.first_seen_at for finding in first.raw_findings
    }

    second = _successful_import(db_session, project=project, target=target, now=second_import_at)

    assert len(db_session.scalars(select(ImportAttempt)).all()) == 2
    assert len(db_session.scalars(select(Scan)).all()) == 2
    assert len(db_session.scalars(select(RawFindingInstance)).all()) == 2
    for finding in second.raw_findings:
        assert finding.first_seen_at == first_seen_by_key[finding.dedupe_key]
        assert finding.last_seen_at == second_import_at
        assert finding.present_in_latest_scan is True
        assert finding.scan is second.scan


def test_absent_findings_are_marked_not_present_without_bumping_last_seen(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    first_import_at = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    second_import_at = first_import_at + timedelta(hours=2)

    first = _successful_import(db_session, project=project, target=target, now=first_import_at)
    present, absent = sorted(first.raw_findings, key=lambda finding: finding.dedupe_key)
    present_first_seen_at = present.first_seen_at
    absent_last_seen_at = absent.last_seen_at
    assert target.target_ref is not None
    parsed_report = ParsedReport(
        scanner="trivy",
        report_kind="trivy-image-json",
        parser_version="1.0",
        target=target.target_ref,
        findings=[
            ParsedFinding(
                scanner=present.scanner_kind,
                scanner_finding_id=present.scanner_finding_id,
                primary_identifier=present.primary_identifier,
                identifiers=present.identifiers_json,
                severity=present.severity,
                dedupe_key=present.dedupe_key,
                cvss=present.cvss_json,
                package_name=present.package_name,
                package_version=present.package_version,
                fixed_version=present.fixed_version,
                artifact_name=present.artifact_name,
                artifact_type=present.artifact_type,
                artifact_path=present.artifact_path,
                references=present.references_json,
                source=present.source_json,
            )
        ],
    )

    persist_parsed_report(
        db_session,
        project=project,
        scan_target=target,
        parsed_report=parsed_report,
        now=second_import_at,
    )

    db_session.refresh(present)
    db_session.refresh(absent)
    assert present.present_in_latest_scan is True
    assert _as_utc(present.first_seen_at) == present_first_seen_at
    assert _as_utc(present.last_seen_at) == second_import_at
    assert absent.present_in_latest_scan is False
    assert _as_utc(absent.last_seen_at) == absent_last_seen_at


def test_project_group_first_detection_uses_earliest_linked_raw_detection(
    db_session: Session,
) -> None:
    project, first_target = _project_and_target(db_session)
    second_target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="worker-image",
        path="images/worker",
        target_ref="registry.example.test/dionysus/worker:2026.05.07",
    )
    db_session.add(second_target)
    db_session.flush()
    later = datetime(2026, 5, 7, 14, 0, tzinfo=UTC)
    earlier = datetime(2026, 5, 7, 10, 0, tzinfo=UTC)

    _successful_import(db_session, project=project, target=first_target, now=later)
    _successful_import(db_session, project=project, target=second_target, now=earlier)

    groups = db_session.scalars(select(ProjectVulnerabilityGroup)).all()
    assert groups
    assert {_as_utc(group.first_detected_at) for group in groups} == {earlier}


def test_failed_import_stores_safe_metadata_without_raw_report_content(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    now = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    secret_payload = b'{"ArtifactName":"secret-registry.example.test/private:latest",'

    with pytest.raises(ImportFailure) as exc_info:
        import_trivy_report(
            db_session,
            project=project,
            scan_target=target,
            payload=secret_payload,
            now=now,
            correlation_id="corr-fail",
        )

    failure = exc_info.value
    attempt = db_session.scalars(select(ImportAttempt)).one()
    assert failure.attempt is attempt
    assert attempt.status == ImportStatus.FAILED
    assert attempt.sanitized_message == "invalid JSON: unable to parse Trivy report"
    assert attempt.correlation_id == "corr-fail"
    assert attempt.metadata_json == {
        "failure_category": "parser_error",
        "raw_report_retained": False,
        "scanner_guess": "trivy",
    }
    assert "secret-registry" not in str(failure)
    assert "private:latest" not in str(failure)
    assert "secret-registry" not in repr(attempt.metadata_json)


def test_parser_failure_creates_failed_attempt_only(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)

    with pytest.raises(ImportFailure):
        import_trivy_report(
            db_session,
            project=project,
            scan_target=target,
            payload=b"{not json",
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert len(db_session.scalars(select(ImportAttempt)).all()) == 1
    assert db_session.scalars(select(ImportAttempt)).one().status == ImportStatus.FAILED
    assert db_session.scalars(select(Scan)).all() == []
    assert db_session.scalars(select(RawFindingInstance)).all() == []
    assert db_session.scalars(select(ProjectVulnerabilityGroup)).all() == []


def test_parser_failure_with_folder_asset_is_rejected_before_recording_target(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    folder = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="images",
        path="images",
    )
    db_session.add(folder)
    db_session.flush()

    with pytest.raises(ImportFailure) as exc_info:
        import_trivy_report(
            db_session,
            project=project,
            scan_target=folder,
            payload=b"{not json",
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    assert not isinstance(exc_info.value.__cause__, ParserError)
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].project is project
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json == {
        "failure_category": "invalid_target_binding",
        "raw_report_retained": False,
        "scanner_guess": "trivy",
    }
    _assert_no_successful_import_artifacts(db_session)


def test_parser_failure_with_cross_project_scan_target_is_rejected_before_recording_target(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    other_project = Project(slug="beta", name="Beta")
    other_target = AssetNode(
        project=other_project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="other-image",
        path="images/other",
        target_ref="registry.example.test/dionysus/other:2026.05.07",
    )
    db_session.add_all([other_project, other_target])
    db_session.flush()

    with pytest.raises(ImportFailure) as exc_info:
        import_trivy_report(
            db_session,
            project=project,
            scan_target=other_target,
            payload=b"{not json",
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    assert not isinstance(exc_info.value.__cause__, ParserError)
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].project is project
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json["failure_category"] == "invalid_target_binding"
    _assert_no_successful_import_artifacts(db_session)


def test_parser_failure_with_transient_target_is_rejected_before_recording_target(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    transient_target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="transient-image",
        path="images/transient",
        target_ref="registry.example.test/dionysus/transient:2026.05.07",
    )

    with pytest.raises(ImportFailure) as exc_info:
        import_trivy_report(
            db_session,
            project=project,
            scan_target=transient_target,
            payload=b"{not json",
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    assert not isinstance(exc_info.value.__cause__, ParserError)
    assert (
        db_session.scalars(select(AssetNode).where(AssetNode.path == "images/transient")).all()
        == []
    )
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].project is project
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json["failure_category"] == "invalid_target_binding"
    _assert_no_successful_import_artifacts(db_session)


def test_persistence_failure_rolls_back_scan_findings_and_records_failed_attempt(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)
    now = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    malformed_finding = ParsedFinding(
        scanner="trivy",
        scanner_finding_id="missing-primary",
        primary_identifier="placeholder",
        identifiers=[],
        severity="HIGH",
        dedupe_key="trivy|bad|missing-primary",
    )
    object.__setattr__(malformed_finding, "primary_identifier", None)
    parsed_report = ParsedReport(
        scanner="trivy",
        report_kind="trivy-image-json",
        parser_version="1.0",
        target="registry.example.test/bad:latest",
        findings=[malformed_finding],
    )

    with pytest.raises(ImportFailure):
        persist_parsed_report(
            db_session,
            project=project,
            scan_target=target,
            parsed_report=parsed_report,
            now=now,
        )

    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].metadata_json["failure_category"] == "persistence_error"
    assert db_session.scalars(select(Scan)).all() == []
    assert db_session.scalars(select(RawFindingInstance)).all() == []
    assert db_session.scalars(select(ProjectVulnerabilityGroup)).all() == []


def test_parser_error_message_is_safe_when_wrapped_by_import_failure(
    db_session: Session,
) -> None:
    project, target = _project_and_target(db_session)

    with pytest.raises(ImportFailure) as exc_info:
        import_trivy_report(
            db_session,
            project=project,
            scan_target=target,
            payload=b'{"ArtifactName":"super-secret.example.test/image:latest",',
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert isinstance(exc_info.value.__cause__, ParserError)
    assert "super-secret" not in str(exc_info.value)


def test_import_with_folder_asset_is_rejected_without_successful_scan_or_findings(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    folder = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="images",
        path="images",
    )
    db_session.add(folder)
    db_session.flush()

    with pytest.raises(ImportFailure) as exc_info:
        persist_parsed_report(
            db_session,
            project=project,
            scan_target=folder,
            parsed_report=_parsed_report(),
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].sanitized_message == "invalid import target binding"
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json["failure_category"] == "invalid_target_binding"
    _assert_no_successful_import_artifacts(db_session)


def test_import_with_scan_target_from_another_project_is_rejected_safely(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    other_project = Project(slug="beta", name="Beta")
    other_target = AssetNode(
        project=other_project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="other-image",
        path="images/other",
        target_ref="registry.example.test/dionysus/other:2026.05.07",
    )
    db_session.add_all([other_project, other_target])
    db_session.flush()

    with pytest.raises(ImportFailure) as exc_info:
        persist_parsed_report(
            db_session,
            project=project,
            scan_target=other_target,
            parsed_report=_parsed_report(),
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].project is project
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json["failure_category"] == "invalid_target_binding"
    _assert_no_successful_import_artifacts(db_session)


def test_import_with_transient_project_is_rejected_without_cascade_persisting_it(
    db_session: Session,
) -> None:
    project = Project(slug="transient", name="Transient")
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="transient-image",
        path="images/transient",
        target_ref="registry.example.test/dionysus/transient:2026.05.07",
    )

    with pytest.raises(ImportFailure) as exc_info:
        persist_parsed_report(
            db_session,
            project=project,
            scan_target=target,
            parsed_report=_parsed_report(),
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    assert db_session.scalars(select(Project).where(Project.slug == "transient")).all() == []
    assert (
        db_session.scalars(select(AssetNode).where(AssetNode.path == "images/transient")).all()
        == []
    )
    assert db_session.scalars(select(ImportAttempt)).all() == []
    _assert_no_successful_import_artifacts(db_session)


def test_import_with_transient_scan_target_is_rejected_without_cascade_persisting_it(
    db_session: Session,
) -> None:
    project, _target = _project_and_target(db_session)
    transient_target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="transient-image",
        path="images/transient",
        target_ref="registry.example.test/dionysus/transient:2026.05.07",
    )

    with pytest.raises(ImportFailure) as exc_info:
        persist_parsed_report(
            db_session,
            project=project,
            scan_target=transient_target,
            parsed_report=_parsed_report(),
            now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        )

    assert str(exc_info.value) == "invalid import target binding"
    assert (
        db_session.scalars(select(AssetNode).where(AssetNode.path == "images/transient")).all()
        == []
    )
    attempts = db_session.scalars(select(ImportAttempt)).all()
    assert len(attempts) == 1
    assert attempts[0].status == ImportStatus.FAILED
    assert attempts[0].project is project
    assert attempts[0].asset_node is None
    assert attempts[0].metadata_json["failure_category"] == "invalid_target_binding"
    _assert_no_successful_import_artifacts(db_session)
