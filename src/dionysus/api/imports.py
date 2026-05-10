"""JSON API routes for scanner report imports."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor, get_authenticated_actor
from dionysus.identity.authorization import ensure_actor_permission
from dionysus.imports.parsers import ParsedReport, ParserError
from dionysus.imports.persistence import (
    ImportFailure,
    ImportResult,
    import_trivy_report,
    import_trivy_report_for_asset,
)
from dionysus.imports.trivy import parse_trivy_image_json
from dionysus.imports.uploads import read_limited_upload
from dionysus.inventory.assets import resolve_folder_path
from dionysus.inventory.projects import get_project
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

router = APIRouter(prefix="/api/imports", tags=["imports"])
authenticated_actor_dependency = Depends(get_authenticated_actor)


class TrivyImportResponse(BaseModel):
    """Response body for a successful Trivy report import."""

    model_config = ConfigDict(extra="forbid")

    import_attempt_id: str
    scan_id: str
    project_id: str
    scan_target_id: str
    scanner: str
    report_kind: str
    finding_count: int
    group_count: int


class TrivyPreviewResponse(BaseModel):
    """Sanitized response body for a Trivy report preview."""

    model_config = ConfigDict(extra="forbid")

    scanner: str
    report_kind: str
    tool_label: str
    detected_asset_name: str
    detected_target_ref: str
    scan_started_at: datetime | None
    finding_count: int
    group_count: int


@router.post("/trivy/preview", response_model=TrivyPreviewResponse)
async def preview_trivy_api(
    request: Request,
    project_id: Annotated[str, Form()],
    report_file: Annotated[UploadFile, File()],
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> TrivyPreviewResponse:
    """Preview sanitized metadata from an uploaded Trivy image JSON report.

    Args:
        request: Incoming request containing application state.
        project_id: Existing project UUID string supplied as multipart form data.
        report_file: Uploaded Trivy JSON report file to parse without persistence.
        actor: Authenticated browser or machine actor resolved by dependency.

    Returns:
        Sanitized report metadata suitable for pre-populating the import form.

    Raises:
        HTTPException: If authentication fails, the project is unknown, the upload
            is oversized, or the report cannot be parsed as supported Trivy JSON.
    """

    max_upload_bytes = request.app.state.settings.max_report_upload_bytes
    payload = await read_limited_upload(report_file, max_upload_bytes)
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="import:upload",
            scope_type="project",
            scope_id=project.id,
        )
        try:
            parsed_report = parse_trivy_image_json(payload)
        except ParserError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return _trivy_preview_response(parsed_report)


@router.post("/trivy", response_model=TrivyImportResponse)
async def import_trivy_api(
    request: Request,
    project_id: Annotated[str, Form()],
    report_file: Annotated[UploadFile, File()],
    scan_target_id: Annotated[str | None, Form()] = None,
    folder_id: Annotated[str | None, Form()] = None,
    folder_path: Annotated[str | None, Form()] = None,
    asset_name: Annotated[str | None, Form()] = None,
    target_ref: Annotated[str | None, Form()] = None,
    scan_started_at: Annotated[str | None, Form()] = None,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> TrivyImportResponse:
    """Import an uploaded Trivy image JSON report through the shared API.

    Args:
        request: Incoming request containing application state.
        project_id: Existing project UUID string supplied as multipart form data.
        scan_target_id: Optional existing project scan target UUID string supplied as form data.
        folder_id: Optional existing project folder UUID string supplied as form data.
        folder_path: Optional slash-delimited folder path to resolve or create for upload binding.
        asset_name: Optional asset display name for folder-bound imports.
        target_ref: Optional scanner-facing asset reference for folder-bound imports.
        report_file: Uploaded Trivy JSON report file.
        scan_started_at: Optional ISO-8601 scan timestamp supplied as form data.
        actor: Authenticated browser or machine actor resolved by dependency.

    Returns:
        JSON summary of the persisted import attempt, scan, and finding counts.

    Raises:
        HTTPException: If authentication fails, the target is unknown, the timestamp
            is invalid, the upload is oversized, or report parsing/import fails.
    """

    max_upload_bytes = request.app.state.settings.max_report_upload_bytes
    payload = await read_limited_upload(report_file, max_upload_bytes)
    parsed_scan_started_at = _parse_optional_datetime(scan_started_at)
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="import:upload",
            scope_type="project",
            scope_id=project.id,
        )
        try:
            result = _import_trivy_with_binding(
                session,
                project=project,
                payload=payload,
                scan_target_id=scan_target_id,
                folder_id=folder_id,
                folder_path=folder_path,
                asset_name=asset_name,
                target_ref=target_ref,
                now=datetime.now(UTC),
                uploader_principal_type=actor.principal_type,
                uploader_principal_id=actor.principal_id,
                scan_started_at=parsed_scan_started_at,
            )
        except ImportFailure as exc:
            failed_target = exc.attempt.asset_node
            record_audit_event(
                session,
                event_type="import.trivy.failure",
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                actor_display=actor.display_name,
                target_type="scan_target" if failed_target is not None else "project",
                target_id=failed_target.id if failed_target is not None else project.id,
                project_id=project.id,
                ip_address=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "scan_target_id": failed_target.id if failed_target is not None else None,
                    "failure_category": exc.attempt.metadata_json.get("failure_category"),
                    "detail": str(exc),
                },
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        record_audit_event(
            session,
            event_type="import.trivy.success",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="scan_target",
            target_id=result.scan.scan_target_id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "scan_target_id": result.scan.scan_target_id,
                "finding_count": len(result.raw_findings),
                "group_count": len(result.groups),
            },
        )
        session.commit()
        return _trivy_import_response(result)


def _get_project_or_404(session: Session, project_id: str) -> Project:
    project = get_project(session, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _get_scan_target_or_404(session: Session, project: Project, scan_target_id: str) -> AssetNode:
    scan_target = session.get(AssetNode, scan_target_id)
    if (
        scan_target is None
        or scan_target.project_id != project.id
        or scan_target.node_type != AssetNodeType.SCAN_TARGET
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan target not found")
    return scan_target


def _get_folder_or_404(session: Session, project: Project, folder_id: str) -> AssetNode:
    folder = session.get(AssetNode, folder_id)
    if (
        folder is None
        or folder.project_id != project.id
        or folder.node_type != AssetNodeType.FOLDER
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    return folder


def _import_trivy_with_binding(
    session: Session,
    *,
    project: Project,
    payload: bytes,
    scan_target_id: str | None,
    folder_id: str | None,
    folder_path: str | None,
    asset_name: str | None,
    target_ref: str | None,
    now: datetime,
    uploader_principal_type: str | None,
    uploader_principal_id: str | None,
    scan_started_at: datetime | None,
) -> ImportResult:
    normalized_scan_target_id = _blank_to_none(scan_target_id)
    normalized_folder_id = _blank_to_none(folder_id)
    normalized_folder_path = _blank_to_none(folder_path)
    folder_bindings = [value for value in (normalized_folder_id, normalized_folder_path) if value]
    if normalized_scan_target_id is not None and folder_bindings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either scan_target_id or folder_id/folder_path, not both",
        )
    if len(folder_bindings) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either folder_id or folder_path, not both",
        )
    if normalized_scan_target_id is not None:
        scan_target = _get_scan_target_or_404(session, project, normalized_scan_target_id)
        return import_trivy_report(
            session,
            project=project,
            scan_target=scan_target,
            payload=payload,
            now=now,
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            scan_started_at=scan_started_at,
        )
    if normalized_folder_id is not None:
        folder = _get_folder_or_404(session, project, normalized_folder_id)
        return import_trivy_report_for_asset(
            session,
            project=project,
            folder=folder,
            payload=payload,
            now=now,
            asset_name=_blank_to_none(asset_name),
            target_ref=_blank_to_none(target_ref),
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            scan_started_at=scan_started_at,
        )
    if normalized_folder_path is not None:
        try:
            folder = resolve_folder_path(session, project, normalized_folder_path)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return import_trivy_report_for_asset(
            session,
            project=project,
            folder=folder,
            payload=payload,
            now=now,
            asset_name=_blank_to_none(asset_name),
            target_ref=_blank_to_none(target_ref),
            uploader_principal_type=uploader_principal_type,
            uploader_principal_id=uploader_principal_id,
            scan_started_at=scan_started_at,
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide scan_target_id, folder_id, or folder_path",
    )


def _blank_to_none(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip()


def _parse_optional_datetime(value: str | None) -> datetime | None:
    if value is None or not value.strip():
        return None
    try:
        normalized = value.strip().removesuffix("Z")
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_started_at must be an ISO-8601 datetime",
        ) from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _trivy_import_response(result: ImportResult) -> TrivyImportResponse:
    return TrivyImportResponse(
        import_attempt_id=result.attempt.id,
        scan_id=result.scan.id,
        project_id=result.scan.project_id,
        scan_target_id=result.scan.scan_target_id,
        scanner=result.scan.scanner_kind,
        report_kind=result.scan.report_kind,
        finding_count=len(result.raw_findings),
        group_count=len(result.groups),
    )


def _trivy_preview_response(parsed_report: ParsedReport) -> TrivyPreviewResponse:
    """Build an API preview response from a parsed Trivy report.

    Args:
        parsed_report: Parsed report produced by the Trivy image parser.

    Returns:
        Sanitized preview fields and finding counts for the UI import form.
    """

    detected_target = parsed_report.target.strip()
    return TrivyPreviewResponse(
        scanner=parsed_report.scanner,
        report_kind=parsed_report.report_kind,
        tool_label="Trivy (Image)",
        detected_asset_name=detected_target,
        detected_target_ref=detected_target,
        scan_started_at=parsed_report.scan_started_at,
        finding_count=len(parsed_report.findings),
        group_count=_parsed_report_group_count(parsed_report),
    )


def _parsed_report_group_count(parsed_report: ParsedReport) -> int:
    """Count distinct primary identifiers in a parsed report.

    Args:
        parsed_report: Parsed report containing normalized finding records.

    Returns:
        Number of distinct primary scanner identifiers found in the report.
    """

    return len({finding.primary_identifier for finding in parsed_report.findings})


def _client_host(request: Request) -> str | None:
    return request.client.host if request.client else None
