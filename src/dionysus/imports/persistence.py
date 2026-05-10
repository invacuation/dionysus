"""Persistence services for scanner report imports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn

from sqlalchemy import inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dionysus.findings.enrichment import enrich_parsed_finding_with_cve_references
from dionysus.imports.parsers import ParsedFinding, ParsedReport, ParserError
from dionysus.imports.trivy import SCANNER, parse_trivy_image_json
from dionysus.inventory.assets import create_or_reuse_scan_target
from dionysus.models.findings import (
    FindingStatus,
    ImportAttempt,
    ImportStatus,
    ProjectVulnerabilityGroup,
    RawFindingInstance,
    Scan,
)
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

_SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class ImportResult:
    """Objects created or updated by a successful import.

    Args:
        attempt: Successful import attempt record.
        scan: Scan record created for the parsed report.
        raw_findings: Raw finding instances created or updated for this import.
        groups: Project vulnerability groups created or updated for this import.
    """

    attempt: ImportAttempt
    scan: Scan
    raw_findings: list[RawFindingInstance]
    groups: list[ProjectVulnerabilityGroup]


class ImportFailure(RuntimeError):  # noqa: N818
    """Safe import failure carrying the persisted failed attempt.

    Args:
        message: Sanitized failure message safe for UI and logs.
        attempt: Failed import attempt persisted for auditability.
    """

    def __init__(self, message: str, *, attempt: ImportAttempt) -> None:
        super().__init__(message)
        self.attempt = attempt


class _InvalidImportTargetBindingError(ValueError):
    """Raised when import project and target binding is not valid."""


def record_failed_import(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode | None,
    parser_name: str,
    scanner_guess: str | None = None,
    failure_category: str,
    sanitized_message: str,
    correlation_id: str | None = None,
    uploader_principal_type: str | None = None,
    uploader_principal_id: str | None = None,
    now: datetime,
) -> ImportAttempt:
    """Record a sanitized failed import attempt without raw report content.

    Args:
        session: SQLAlchemy session used by the caller.
        project: Existing project that owns the import.
        scan_target: Existing asset node selected as the scan target, when safe to bind.
        parser_name: Parser or report format attempted.
        scanner_guess: Best-effort scanner kind, when known before parsing succeeds.
        failure_category: Stable category such as ``parser_error``.
        sanitized_message: Safe message that does not include raw payload content.
        correlation_id: Optional request or job correlation identifier.
        uploader_principal_type: Optional uploader principal type.
        uploader_principal_id: Optional uploader principal ID.
        now: Timestamp to store as import metadata.

    Returns:
        The flushed failed import attempt.
    """

    attempt = ImportAttempt(
        project=project,
        asset_node=scan_target,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        status=ImportStatus.FAILED,
        parser_name=parser_name,
        sanitized_message=sanitized_message,
        correlation_id=correlation_id,
        metadata_json={
            "failure_category": failure_category,
            "raw_report_retained": False,
            **({"scanner_guess": scanner_guess} if scanner_guess else {}),
        },
    )
    session.add(attempt)
    session.flush([attempt])
    return attempt


def persist_parsed_report(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode,
    parsed_report: ParsedReport,
    now: datetime,
    uploader_principal_type: str | None = None,
    uploader_principal_id: str | None = None,
    scan_started_at: datetime | None = None,
    correlation_id: str | None = None,
) -> ImportResult:
    """Persist normalized scanner findings using service-layer upsert rules.

    The service flushes changes but leaves commit control to the caller. On
    persistence failure, scan and finding writes are rolled back and a sanitized
    failed import attempt is flushed.

    Args:
        session: SQLAlchemy session used by the caller.
        project: Existing project that owns the import.
        scan_target: Existing asset node selected as the scan target.
        parsed_report: Scanner-agnostic parsed report.
        now: Import timestamp used for detection fields.
        uploader_principal_type: Optional uploader principal type.
        uploader_principal_id: Optional uploader principal ID.
        scan_started_at: Optional route-provided scan start timestamp.
        correlation_id: Optional request or job correlation identifier.

    Returns:
        Import result containing flushed ORM records.

    Raises:
        ImportFailure: If persistence fails. The exception message is sanitized
            and carries the failed attempt record.
    """

    parser_name = parsed_report.report_kind
    try:
        project, scan_target = _validate_import_target_binding(
            session,
            project=project,
            scan_target=scan_target,
        )
    except _InvalidImportTargetBindingError as exc:
        attempt = _record_invalid_target_binding_failure(
            session,
            project=project,
            scan_target=scan_target,
            parser_name=parser_name,
            scanner_guess=parsed_report.scanner,
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure("invalid import target binding", attempt=attempt) from exc

    try:
        with session.begin_nested():
            attempt = ImportAttempt(
                project=project,
                asset_node=scan_target,
                uploader_principal_type=uploader_principal_type,
                uploader_principal_id=uploader_principal_id,
                status=ImportStatus.SUCCESS,
                parser_name=parser_name,
                sanitized_message="import completed",
                correlation_id=correlation_id,
                metadata_json={
                    "raw_report_retained": False,
                    "scanner": parsed_report.scanner,
                    "finding_count": len(parsed_report.findings),
                },
            )
            scan = Scan(
                project=project,
                scan_target=scan_target,
                scanner_kind=parsed_report.scanner,
                report_kind=parsed_report.report_kind,
                parser_version=parsed_report.parser_version,
                scan_started_at=scan_started_at or parsed_report.scan_started_at,
                scan_finished_at=parsed_report.scan_finished_at or now,
                metadata_json=parsed_report.metadata,
            )
            session.add_all([attempt, scan])
            session.flush()

            raw_findings: list[RawFindingInstance] = []
            groups_by_dedupe_key: dict[str, ProjectVulnerabilityGroup] = {}
            group_cache: dict[str, ProjectVulnerabilityGroup] = {}
            present_dedupe_keys: set[str] = set()
            for parsed_finding in parsed_report.findings:
                finding = enrich_parsed_finding_with_cve_references(parsed_finding)
                _validate_finding(finding)
                present_dedupe_keys.add(finding.dedupe_key)
                raw_finding = _upsert_raw_finding(
                    session,
                    project=project,
                    scan_target=scan_target,
                    scan=scan,
                    finding=finding,
                    now=now,
                )
                group = _upsert_group(
                    session,
                    project=project,
                    finding=finding,
                    first_detected_at=raw_finding.first_seen_at,
                    group_cache=group_cache,
                )
                raw_findings.append(raw_finding)
                groups_by_dedupe_key.setdefault(group.dedupe_key, group)

            _mark_absent_raw_findings_not_present(
                session,
                scan_target=scan_target,
                present_dedupe_keys=present_dedupe_keys,
            )
            session.flush()
            return ImportResult(
                attempt=attempt,
                scan=scan,
                raw_findings=raw_findings,
                groups=list(groups_by_dedupe_key.values()),
            )
    except (SQLAlchemyError, ValueError) as exc:
        attempt = record_failed_import(
            session,
            project=project,
            scan_target=scan_target,
            parser_name=parser_name,
            scanner_guess=parsed_report.scanner,
            failure_category="persistence_error",
            sanitized_message="unable to persist parsed report",
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure("unable to persist parsed report", attempt=attempt) from exc


def import_trivy_report(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode,
    payload: bytes | str,
    now: datetime,
    uploader_principal_type: str | None = None,
    uploader_principal_id: str | None = None,
    scan_started_at: datetime | None = None,
    correlation_id: str | None = None,
) -> ImportResult:
    """Parse and persist a Trivy image JSON report safely.

    Args:
        session: SQLAlchemy session used by the caller.
        project: Existing project that owns the import.
        scan_target: Existing asset node selected as the scan target.
        payload: Raw Trivy report content. It is parsed but not stored.
        now: Import timestamp used for detection fields.
        uploader_principal_type: Optional uploader principal type.
        uploader_principal_id: Optional uploader principal ID.
        scan_started_at: Optional route-provided scan start timestamp.
        correlation_id: Optional request or job correlation identifier.

    Returns:
        Import result containing flushed ORM records.

    Raises:
        ImportFailure: If parsing or persistence fails. The exception message is
            sanitized and carries the failed attempt record.
    """

    try:
        project, scan_target = _validate_import_target_binding(
            session,
            project=project,
            scan_target=scan_target,
        )
    except _InvalidImportTargetBindingError as exc:
        attempt = _record_invalid_target_binding_failure(
            session,
            project=project,
            scan_target=scan_target,
            parser_name="trivy-image-json",
            scanner_guess=SCANNER,
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure("invalid import target binding", attempt=attempt) from exc

    parsed_report = _parse_trivy_report_or_fail(
        session,
        project=project,
        scan_target=scan_target,
        payload=payload,
        correlation_id=correlation_id,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        now=now,
    )

    return persist_parsed_report(
        session,
        project=project,
        scan_target=scan_target,
        parsed_report=parsed_report,
        now=now,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        scan_started_at=scan_started_at,
        correlation_id=correlation_id,
    )


def import_trivy_report_for_asset(
    session: Session,
    *,
    project: Project,
    folder: AssetNode,
    payload: bytes | str,
    now: datetime,
    asset_name: str | None = None,
    target_ref: str | None = None,
    uploader_principal_type: str | None = None,
    uploader_principal_id: str | None = None,
    scan_started_at: datetime | None = None,
    correlation_id: str | None = None,
) -> ImportResult:
    """Parse a Trivy report, bind it to a folder asset, and persist findings.

    Args:
        session: SQLAlchemy session used by the caller.
        project: Existing project that owns the import.
        folder: Existing folder where the scanned asset should live.
        payload: Raw Trivy report content. It is parsed but not stored.
        now: Import timestamp used for detection fields.
        asset_name: Optional user-facing asset name, falling back to report target.
        target_ref: Optional scanner-facing reference, falling back to report target.
        uploader_principal_type: Optional uploader principal type.
        uploader_principal_id: Optional uploader principal ID.
        scan_started_at: Optional route-provided scan start timestamp.
        correlation_id: Optional request or job correlation identifier.

    Returns:
        Import result containing flushed ORM records.

    Raises:
        ImportFailure: If parsing, target creation, or persistence fails.
    """

    parsed_report = _parse_trivy_report_or_fail(
        session,
        project=project,
        scan_target=None,
        payload=payload,
        correlation_id=correlation_id,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        now=now,
    )
    resolved_target_ref = (target_ref or parsed_report.target).strip()
    resolved_asset_name = (asset_name or resolved_target_ref).strip()
    if not resolved_asset_name or not resolved_target_ref:
        attempt = record_failed_import(
            session,
            project=project,
            scan_target=None,
            parser_name=parsed_report.report_kind,
            scanner_guess=parsed_report.scanner,
            failure_category="missing_asset_details",
            sanitized_message="asset_name or detected report target is required",
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure("asset_name or detected report target is required", attempt=attempt)

    try:
        scan_target = create_or_reuse_scan_target(
            session,
            project=project,
            folder=folder,
            name=resolved_asset_name,
            target_ref=resolved_target_ref,
            metadata_json={
                "source": "import_upload",
                "scanner": parsed_report.scanner,
                "report_kind": parsed_report.report_kind,
            },
        )
    except ValueError as exc:
        attempt = record_failed_import(
            session,
            project=project,
            scan_target=None,
            parser_name=parsed_report.report_kind,
            scanner_guess=parsed_report.scanner,
            failure_category="asset_binding_error",
            sanitized_message=str(exc),
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure(str(exc), attempt=attempt) from exc

    return persist_parsed_report(
        session,
        project=project,
        scan_target=scan_target,
        parsed_report=parsed_report,
        now=now,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        scan_started_at=scan_started_at,
        correlation_id=correlation_id,
    )


def _parse_trivy_report_or_fail(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode | None,
    payload: bytes | str,
    correlation_id: str | None,
    uploader_principal_type: str | None,
    uploader_principal_id: str | None,
    now: datetime,
) -> ParsedReport:
    try:
        return parse_trivy_image_json(payload)
    except ParserError as exc:
        attempt = record_failed_import(
            session,
            project=project,
            scan_target=scan_target,
            parser_name="trivy-image-json",
            scanner_guess=SCANNER,
            failure_category="parser_error",
            sanitized_message=str(exc),
            correlation_id=correlation_id,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            now=now,
        )
        raise ImportFailure(str(exc), attempt=attempt) from exc


def _validate_import_target_binding(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode,
) -> tuple[Project, AssetNode]:
    with session.no_autoflush:
        project_identity = inspect(project).identity
        scan_target_identity = inspect(scan_target).identity
        if project_identity is None or scan_target_identity is None:
            raise _InvalidImportTargetBindingError

        persisted_project = session.get(Project, project_identity[0])
        persisted_scan_target = session.get(AssetNode, scan_target_identity[0])

    if persisted_project is None or persisted_scan_target is None:
        raise _InvalidImportTargetBindingError
    if persisted_scan_target.project_id != persisted_project.id:
        raise _InvalidImportTargetBindingError
    if persisted_scan_target.node_type != AssetNodeType.SCAN_TARGET:
        raise _InvalidImportTargetBindingError

    return persisted_project, persisted_scan_target


def _record_invalid_target_binding_failure(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode,
    parser_name: str,
    scanner_guess: str | None,
    correlation_id: str | None,
    uploader_principal_type: str | None,
    uploader_principal_id: str | None,
    now: datetime,
) -> ImportAttempt:
    with session.no_autoflush:
        project_identity = inspect(project).identity
        persisted_project = (
            session.get(Project, project_identity[0]) if project_identity is not None else None
        )

        scan_target_identity = inspect(scan_target).identity
        persisted_scan_target = (
            session.get(AssetNode, scan_target_identity[0])
            if scan_target_identity is not None
            else None
        )

    if persisted_project is None:
        return ImportAttempt(
            status=ImportStatus.FAILED,
            parser_name=parser_name,
            sanitized_message="invalid import target binding",
            correlation_id=correlation_id,
            metadata_json={
                "failure_category": "invalid_target_binding",
                "raw_report_retained": False,
                **({"scanner_guess": scanner_guess} if scanner_guess else {}),
            },
        )

    safe_scan_target = (
        persisted_scan_target
        if persisted_scan_target is not None
        and persisted_scan_target.project_id == persisted_project.id
        and persisted_scan_target.node_type == AssetNodeType.SCAN_TARGET
        else None
    )

    return record_failed_import(
        session,
        project=persisted_project,
        scan_target=safe_scan_target,
        parser_name=parser_name,
        scanner_guess=scanner_guess,
        failure_category="invalid_target_binding",
        sanitized_message="invalid import target binding",
        correlation_id=correlation_id,
        uploader_principal_type=uploader_principal_type,
        uploader_principal_id=uploader_principal_id,
        now=now,
    )


def _upsert_raw_finding(
    session: Session,
    *,
    project: Project,
    scan_target: AssetNode,
    scan: Scan,
    finding: ParsedFinding,
    now: datetime,
) -> RawFindingInstance:
    existing = session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.scan_target_id == scan_target.id,
            RawFindingInstance.dedupe_key == finding.dedupe_key,
        )
    ).one_or_none()

    if existing is None:
        raw_finding = RawFindingInstance(
            project=project,
            scan=scan,
            scan_target=scan_target,
            scanner_kind=finding.scanner,
            scanner_finding_id=finding.scanner_finding_id,
            dedupe_key=finding.dedupe_key,
            identifiers_json=finding.identifiers,
            primary_identifier=finding.primary_identifier,
            severity=finding.severity,
            cvss_json=finding.cvss,
            package_name=finding.package_name,
            package_version=finding.package_version,
            fixed_version=finding.fixed_version,
            artifact_name=finding.artifact_name,
            artifact_type=finding.artifact_type,
            artifact_path=finding.artifact_path or finding.package_path,
            first_seen_at=now,
            last_seen_at=now,
            present_in_latest_scan=True,
            status=FindingStatus.OPEN,
            references_json=finding.references,
            source_json=finding.source,
        )
        session.add(raw_finding)
        return raw_finding

    existing.scan = scan
    existing.scanner_kind = finding.scanner
    existing.scanner_finding_id = finding.scanner_finding_id
    existing.identifiers_json = finding.identifiers
    existing.primary_identifier = finding.primary_identifier
    existing.severity = finding.severity
    existing.cvss_json = finding.cvss
    existing.package_name = finding.package_name
    existing.package_version = finding.package_version
    existing.fixed_version = finding.fixed_version
    existing.artifact_name = finding.artifact_name
    existing.artifact_type = finding.artifact_type
    existing.artifact_path = finding.artifact_path or finding.package_path
    existing.last_seen_at = now
    existing.present_in_latest_scan = True
    existing.references_json = finding.references
    existing.source_json = finding.source
    return existing


def _mark_absent_raw_findings_not_present(
    session: Session,
    *,
    scan_target: AssetNode,
    present_dedupe_keys: set[str],
) -> None:
    statement = select(RawFindingInstance).where(
        RawFindingInstance.scan_target_id == scan_target.id,
        RawFindingInstance.present_in_latest_scan.is_(True),
    )
    if present_dedupe_keys:
        statement = statement.where(RawFindingInstance.dedupe_key.not_in(present_dedupe_keys))

    for raw_finding in session.scalars(statement):
        raw_finding.present_in_latest_scan = False


def _upsert_group(
    session: Session,
    *,
    project: Project,
    finding: ParsedFinding,
    first_detected_at: datetime,
    group_cache: dict[str, ProjectVulnerabilityGroup],
) -> ProjectVulnerabilityGroup:
    dedupe_key = finding.primary_identifier
    if dedupe_key in group_cache:
        return _update_group(
            group_cache[dedupe_key],
            finding=finding,
            first_detected_at=first_detected_at,
        )

    existing = session.scalars(
        select(ProjectVulnerabilityGroup).where(
            ProjectVulnerabilityGroup.project_id == project.id,
            ProjectVulnerabilityGroup.dedupe_key == dedupe_key,
        )
    ).one_or_none()

    if existing is None:
        group = ProjectVulnerabilityGroup(
            project=project,
            primary_identifier=finding.primary_identifier,
            additional_identifiers_json=finding.additional_identifiers,
            first_detected_at=first_detected_at,
            severity=finding.severity,
            status=FindingStatus.OPEN,
            dedupe_key=dedupe_key,
        )
        session.add(group)
        group_cache[dedupe_key] = group
        return group

    group_cache[dedupe_key] = existing
    return _update_group(
        existing,
        finding=finding,
        first_detected_at=first_detected_at,
    )


def _update_group(
    group: ProjectVulnerabilityGroup,
    *,
    finding: ParsedFinding,
    first_detected_at: datetime,
) -> ProjectVulnerabilityGroup:
    group.primary_identifier = finding.primary_identifier
    group.additional_identifiers_json = _merge_identifiers(
        group.additional_identifiers_json,
        finding.additional_identifiers,
    )
    group.first_detected_at = _earliest_datetime(group.first_detected_at, first_detected_at)
    group.severity = _highest_severity(group.severity, finding.severity)
    return group


def _validate_finding(finding: ParsedFinding) -> None:
    if not finding.scanner:
        _raise_validation_error("finding scanner is required")
    if not finding.scanner_finding_id:
        _raise_validation_error("finding scanner ID is required")
    if not finding.primary_identifier:
        _raise_validation_error("finding primary identifier is required")
    if not finding.dedupe_key:
        _raise_validation_error("finding dedupe key is required")


def _raise_validation_error(message: str) -> NoReturn:
    raise ValueError(message)


def _merge_identifiers(existing: list[str], incoming: list[str]) -> list[str]:
    seen = set(existing)
    merged = list(existing)
    for identifier in incoming:
        if identifier not in seen:
            merged.append(identifier)
            seen.add(identifier)
    return merged


def _highest_severity(left: str, right: str) -> str:
    return left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right


def _earliest_datetime(left: datetime, right: datetime) -> datetime:
    left_comparable = left if left.tzinfo is not None else left.replace(tzinfo=UTC)
    right_comparable = right if right.tzinfo is not None else right.replace(tzinfo=UTC)
    return left if left_comparable <= right_comparable else right
