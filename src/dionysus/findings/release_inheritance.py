"""Release-scoped finding inheritance helpers."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from dionysus.models.findings import (
    FindingComment,
    FindingReleaseStatusDecision,
    FindingStatus,
    FindingStatusChangeRequest,
    RawFindingInstance,
    Scan,
)
from dionysus.models.inventory import AssetNode


@dataclass(frozen=True)
class ReleaseContext:
    """Resolved release inheritance scope and version for a scan target."""

    scope_asset_id: str
    scope_path: str
    version_asset_id: str
    version_path: str
    version: str


@dataclass(frozen=True)
class RelatedReleaseOccurrence:
    """One raw finding occurrence for the same release-scoped finding identity."""

    finding_id: str
    release_version: str
    project_name: str
    scan_target_name: str
    scan_target_path: str
    status: str
    present_in_latest_scan: bool
    installed_version: str | None
    fixed_version: str | None


def _metadata(node: AssetNode) -> dict[str, object] | None:
    metadata = node.metadata_json
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        return None
    return metadata


def release_context_for_scan_target(
    session: Session,
    scan_target: AssetNode,
) -> ReleaseContext | None:
    """Resolve the release inheritance context for a scan target."""

    if scan_target.project_id is None:
        return None

    path_from_target: list[AssetNode] = []
    current: AssetNode | None = scan_target
    while current is not None:
        if current.project_id != scan_target.project_id:
            return None
        if _metadata(current) is None:
            return None
        path_from_target.append(current)

        if current.parent_id is None:
            current = None
            continue

        parent = current.parent
        if parent is None:
            parent = session.get(AssetNode, current.parent_id)
        if parent is None:
            return None
        current = parent

    path_from_root = list(reversed(path_from_target))
    for index in range(len(path_from_root) - 2, -1, -1):
        ancestor = path_from_root[index]
        if ancestor.node_type != "folder":
            continue
        metadata = _metadata(ancestor)
        if metadata is None:
            return None
        if metadata.get("release_inheritance_scope") is not True:
            continue

        release_version_asset = path_from_root[index + 1]
        if release_version_asset.node_type != "folder":
            return None
        version_metadata = _metadata(release_version_asset)
        if version_metadata is None:
            return None

        metadata_version = version_metadata.get("release_version")
        version = str(metadata_version).strip() if metadata_version is not None else ""
        if not version:
            version = release_version_asset.name.strip()
        if not version:
            return None

        return ReleaseContext(
            scope_asset_id=ancestor.id,
            scope_path=ancestor.path,
            version_asset_id=release_version_asset.id,
            version_path=release_version_asset.path,
            version=version,
        )

    return None


def finding_inheritance_identity(primary_identifier: str, package_name: str | None) -> str:
    """Build the stable identity used for release inheritance decisions."""

    normalized_identifier = primary_identifier.strip()
    if not normalized_identifier:
        raise ValueError("primary_identifier must not be blank")
    normalized_package = package_name.strip() if package_name is not None else ""
    return f"{normalized_identifier}|{normalized_package}"


def related_occurrences_for_finding(
    session: Session,
    finding: RawFindingInstance,
) -> list[RelatedReleaseOccurrence]:
    """Return same-identity raw finding occurrences in the same release scope."""

    context = release_context_for_scan_target(session, finding.scan_target)
    if context is None:
        return []
    finding_identity = finding_inheritance_identity(
        finding.primary_identifier,
        finding.package_name,
    )
    normalized_identifier = finding.primary_identifier.strip()
    normalized_package = finding.package_name.strip() if finding.package_name is not None else ""
    scope_path_like = _escape_like_pattern(context.scope_path)

    candidates_statement = (
        select(RawFindingInstance)
        .join(Scan, RawFindingInstance.scan_id == Scan.id)
        .join(AssetNode, RawFindingInstance.scan_target_id == AssetNode.id)
        .options(
            selectinload(RawFindingInstance.project),
            selectinload(RawFindingInstance.scan_target),
        )
        .where(
            RawFindingInstance.project_id == finding.project_id,
            RawFindingInstance.scanner_kind == str(finding.scanner_kind),
            Scan.report_kind == finding.scan.report_kind,
            func.trim(RawFindingInstance.primary_identifier) == normalized_identifier,
            func.trim(func.coalesce(RawFindingInstance.package_name, "")) == normalized_package,
            or_(
                AssetNode.path == context.scope_path,
                AssetNode.path.like(f"{scope_path_like}/%", escape="\\"),
            ),
        )
    )

    occurrences: list[tuple[ReleaseContext, RawFindingInstance]] = []
    for candidate in session.scalars(candidates_statement).all():
        if (
            finding_inheritance_identity(
                candidate.primary_identifier,
                candidate.package_name,
            )
            != finding_identity
        ):
            continue
        candidate_context = release_context_for_scan_target(session, candidate.scan_target)
        if candidate_context is None:
            continue
        if candidate_context.scope_asset_id != context.scope_asset_id:
            continue
        occurrences.append((candidate_context, candidate))

    occurrences.sort(key=lambda item: _release_occurrence_sort_key(item[0], item[1]))
    return [
        RelatedReleaseOccurrence(
            finding_id=candidate.id,
            release_version=candidate_context.version,
            project_name=candidate.project.name,
            scan_target_name=candidate.scan_target.name,
            scan_target_path=candidate.scan_target.path,
            status=candidate.status,
            present_in_latest_scan=candidate.present_in_latest_scan,
            installed_version=candidate.package_version,
            fixed_version=candidate.fixed_version,
        )
        for candidate_context, candidate in occurrences
    ]


def _release_occurrence_sort_key(
    context: ReleaseContext,
    finding: RawFindingInstance,
) -> tuple[int, tuple[int, ...] | tuple[str], str]:
    numeric_version = _parse_numeric_version(context.version)
    if numeric_version is not None:
        return (0, numeric_version, finding.id)
    return (1, (context.version,), finding.id)


def _escape_like_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_numeric_version(version: str) -> tuple[int, ...] | None:
    parts = version.strip().split(".")
    if not parts or any(part == "" or not part.isdecimal() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _pad_version(version: tuple[int, ...], length: int) -> tuple[int, ...]:
    return version + (0,) * (length - len(version))


def latest_applicable_decision(
    session: Session,
    *,
    project_id: str,
    context: ReleaseContext,
    scanner_kind: str,
    report_kind: str,
    finding_identity: str,
) -> FindingReleaseStatusDecision | None:
    """Return the newest release decision applicable to the context version."""

    decisions = session.scalars(
        select(FindingReleaseStatusDecision).where(
            FindingReleaseStatusDecision.project_id == project_id,
            FindingReleaseStatusDecision.release_scope_asset_id == context.scope_asset_id,
            FindingReleaseStatusDecision.scanner_kind == str(scanner_kind),
            FindingReleaseStatusDecision.report_kind == report_kind,
            FindingReleaseStatusDecision.finding_identity == finding_identity,
        )
    ).all()

    target_numeric_version = _parse_numeric_version(context.version)
    numeric_candidates: list[tuple[tuple[int, ...], FindingReleaseStatusDecision]] = []
    exact_non_numeric_candidates: list[tuple[tuple[int, ...], FindingReleaseStatusDecision]] = []
    max_numeric_length = len(target_numeric_version or ())
    for decision in decisions:
        decision_numeric_version = _parse_numeric_version(decision.release_version)
        if target_numeric_version is not None and decision_numeric_version is not None:
            max_numeric_length = max(max_numeric_length, len(decision_numeric_version))
            numeric_candidates.append((decision_numeric_version, decision))
        elif decision.release_version == context.version:
            exact_non_numeric_candidates.append(((), decision))

    comparable: list[tuple[tuple[int, ...], datetime, datetime, str, FindingReleaseStatusDecision]]
    comparable = []
    if target_numeric_version is not None:
        target_key = _pad_version(target_numeric_version, max_numeric_length)
        for decision_numeric_version, decision in numeric_candidates:
            version_key = _pad_version(decision_numeric_version, max_numeric_length)
            if version_key > target_key:
                continue
            comparable.append(
                (
                    version_key,
                    decision.decided_at,
                    decision.created_at,
                    decision.id,
                    decision,
                )
            )

    for version_key, decision in exact_non_numeric_candidates:
        comparable.append(
            (
                version_key,
                decision.decided_at,
                decision.created_at,
                decision.id,
                decision,
            )
        )

    if not comparable:
        return None
    return max(comparable, key=lambda item: item[:-1])[-1]


def record_release_status_decision(
    session: Session,
    *,
    finding: RawFindingInstance,
    status: str | FindingStatus,
    comment: FindingComment | None = None,
    request: FindingStatusChangeRequest | None = None,
    decided_at: datetime | None = None,
) -> FindingReleaseStatusDecision | None:
    """Create or update the release status decision represented by a finding."""

    context = release_context_for_scan_target(session, finding.scan_target)
    if context is None:
        return None

    identity = finding_inheritance_identity(finding.primary_identifier, finding.package_name)
    normalized_status = FindingStatus(status)
    decision = session.scalars(
        select(FindingReleaseStatusDecision).where(
            FindingReleaseStatusDecision.project_id == finding.project_id,
            FindingReleaseStatusDecision.release_scope_asset_id == context.scope_asset_id,
            FindingReleaseStatusDecision.release_version_asset_id == context.version_asset_id,
            FindingReleaseStatusDecision.scanner_kind == str(finding.scanner_kind),
            FindingReleaseStatusDecision.report_kind == finding.scan.report_kind,
            FindingReleaseStatusDecision.finding_identity == identity,
        )
    ).one_or_none()

    if decision is None:
        release_scope_asset = session.get(AssetNode, context.scope_asset_id)
        release_version_asset = session.get(AssetNode, context.version_asset_id)
        decision = FindingReleaseStatusDecision(
            project=finding.project,
            release_scope_asset=release_scope_asset,
            release_version_asset=release_version_asset,
            scanner_kind=str(finding.scanner_kind),
            report_kind=finding.scan.report_kind,
            finding_identity=identity,
        )
        session.add(decision)

    decision.release_version = context.version
    decision.source_finding = finding
    decision.source_comment = comment
    decision.source_request = request
    decision.status = normalized_status
    decision.decided_at = decided_at or datetime.now(UTC)

    return decision
