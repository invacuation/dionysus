"""JSON API routes for project and asset inventory data."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dionysus.audit import record_audit_event
from dionysus.identity.actors import AuthenticatedActor, get_authenticated_actor
from dionysus.identity.authorization import actor_has_permission, ensure_actor_permission
from dionysus.inventory.assets import (
    count_asset_subtree,
    count_project_assets,
    create_scan_target,
    delete_asset_node,
    list_project_assets,
    move_asset_node,
    rename_asset_node,
    resolve_folder_path,
    set_asset_sla_overrides,
)
from dionysus.inventory.projects import (
    create_project,
    delete_project,
    get_project,
    list_projects,
    update_project,
)
from dionysus.models.findings import Scan, ScannerKind
from dionysus.models.inventory import AssetNode, Project

router = APIRouter(prefix="/api/projects", tags=["inventory"])
authenticated_actor_dependency = Depends(get_authenticated_actor)


class ProjectResponse(BaseModel):
    """Project inventory metadata for React API consumers."""

    model_config = ConfigDict(extra="forbid")

    id: str
    slug: str
    name: str
    description: str | None
    sla_tracking_enabled: bool
    sla_reporting_enabled: bool
    require_peer_review_for_status_changes: bool
    grace_period_enabled: bool
    grace_period_percent: int


class ProjectListResponse(BaseModel):
    """Response body for project inventory list queries."""

    model_config = ConfigDict(extra="forbid")

    projects: list[ProjectResponse]


class AssetResponse(BaseModel):
    """Asset inventory node metadata for React API consumers."""

    model_config = ConfigDict(extra="forbid")

    id: str
    parent_id: str | None
    path: str
    type: str
    name: str
    target_ref: str | None
    scan_label: str | None
    sla_tracking_enabled: bool | None
    sla_reporting_enabled: bool | None
    sort_order: int


class ProjectAssetsResponse(BaseModel):
    """Response body for a project's asset inventory nodes."""

    model_config = ConfigDict(extra="forbid")

    project_id: str
    assets: list[AssetResponse]


class ProjectCreateRequest(BaseModel):
    """Request body for project creation."""

    model_config = ConfigDict(extra="forbid")

    slug: str
    name: str
    description: str | None = None
    sla_tracking_enabled: bool = True
    sla_reporting_enabled: bool = True
    require_peer_review_for_status_changes: bool = False
    grace_period_enabled: bool = False
    grace_period_percent: int = 100


class ProjectUpdateRequest(BaseModel):
    """Request body for project settings mutation."""

    model_config = ConfigDict(extra="forbid")

    slug: str | None = None
    name: str | None = None
    require_peer_review_for_status_changes: bool | None = None
    grace_period_enabled: bool | None = None
    grace_period_percent: int | None = None


class FolderResolveRequest(BaseModel):
    """Request body for folder path resolution."""

    model_config = ConfigDict(extra="forbid")

    path: str


class ScanTargetCreateRequest(BaseModel):
    """Request body for scan target creation."""

    model_config = ConfigDict(extra="forbid")

    folder_path: str
    name: str
    target_ref: str
    node_type: str = "scan_target"
    metadata: dict[str, Any] | None = None


class AssetUpdateRequest(BaseModel):
    """Request body for asset node mutation."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    parent_id: str | None = None
    sla_tracking_enabled: bool | None = None
    sla_reporting_enabled: bool | None = None


@router.get("", response_model=ProjectListResponse)
def project_list_api(
    request: Request,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> ProjectListResponse:
    """Return projects for the React frontend.

    Args:
        request: Incoming request containing application state.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable projects sorted by the inventory project service.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        projects = list_projects(session)
        visible_projects = [
            project
            for project in projects
            if actor_has_permission(
                session,
                actor=actor,
                permission="project:view",
                scope_type="project",
                scope_id=project.id,
            )
        ]
        return ProjectListResponse(
            projects=[_project_response(project) for project in visible_projects]
        )


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def project_create_api(
    request: Request,
    payload: ProjectCreateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> ProjectResponse:
    """Create an inventory project.

    Args:
        request: Incoming request containing application state.
        payload: Project creation fields supplied as JSON.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable project metadata for the created project.

    Raises:
        HTTPException: If validation fails or slug/name uniqueness is violated.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        ensure_actor_permission(
            session,
            actor=actor,
            permission="project:create",
            scope_type=None,
            scope_id=None,
        )
        try:
            project = create_project(
                session,
                slug=payload.slug,
                name=payload.name,
                description=payload.description,
                sla_tracking_enabled=payload.sla_tracking_enabled,
                sla_reporting_enabled=payload.sla_reporting_enabled,
                require_peer_review_for_status_changes=(
                    payload.require_peer_review_for_status_changes
                ),
                grace_period_enabled=payload.grace_period_enabled,
                grace_period_percent=payload.grace_period_percent,
            )
        except ValueError as exc:
            raise _bad_request(str(exc)) from exc
        except IntegrityError as exc:
            session.rollback()
            raise _project_conflict() from exc
        record_audit_event(
            session,
            event_type="inventory.project.create",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="project",
            target_id=project.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"slug": project.slug, "name": project.name},
        )
        session.commit()
        return _project_response(project)


@router.patch("/{project_id}", response_model=ProjectResponse)
def project_update_api(
    request: Request,
    project_id: str,
    payload: ProjectUpdateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> ProjectResponse:
    """Update mutable project settings.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string to update.
        payload: Project settings fields supplied as JSON.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable project metadata after mutation.

    Raises:
        HTTPException: If the project ID is unknown.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="project:update",
            scope_type="project",
            scope_id=project.id,
        )
        changes = _project_update_changes(project, payload)
        try:
            if "slug" in payload.model_fields_set:
                if payload.slug is None:
                    raise ValueError("project slug must be non-empty")
                update_project(session, project, slug=payload.slug)
            if "name" in payload.model_fields_set:
                if payload.name is None:
                    raise ValueError("project name must be non-empty")
                update_project(session, project, name=payload.name)
            if "require_peer_review_for_status_changes" in payload.model_fields_set:
                require_peer_review = payload.require_peer_review_for_status_changes
                if require_peer_review is None:
                    raise _bad_request("require_peer_review_for_status_changes must be a boolean")
                project.require_peer_review_for_status_changes = require_peer_review
            if "grace_period_enabled" in payload.model_fields_set:
                grace_period_enabled = payload.grace_period_enabled
                if grace_period_enabled is None:
                    raise _bad_request("grace_period_enabled must be a boolean")
                project.grace_period_enabled = grace_period_enabled
            if "grace_period_percent" in payload.model_fields_set:
                grace_period_percent = payload.grace_period_percent
                if grace_period_percent is None or grace_period_percent <= 0:
                    raise _bad_request("grace_period_percent must be a positive integer")
                project.grace_period_percent = grace_period_percent
        except ValueError as exc:
            if str(exc) == "project slug or name already exists":
                raise _project_conflict() from exc
            raise _bad_request(str(exc)) from exc
        except IntegrityError as exc:
            session.rollback()
            raise _project_conflict() from exc
        if changes:
            record_audit_event(
                session,
                event_type="inventory.project.update",
                actor_principal_type=actor.principal_type,
                actor_principal_id=actor.principal_id,
                actor_display=actor.display_name,
                target_type="project",
                target_id=project.id,
                project_id=project.id,
                ip_address=_client_host(request),
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "changed_fields": list(changes),
                    "changes": changes,
                },
            )
        session.commit()
        return _project_response(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def project_delete_api(
    request: Request,
    project_id: str,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> Response:
    """Delete a project and dependent inventory/finding data.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string to delete.
        actor: Authenticated request actor required for access.

    Returns:
        Empty 204 response after deletion.

    Raises:
        HTTPException: If the project is unknown or actor lacks permission.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="project:delete",
            scope_type="project",
            scope_id=project.id,
        )
        deleted_asset_count = count_project_assets(session, project)
        record_audit_event(
            session,
            event_type="inventory.project.delete",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="project",
            target_id=project.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "slug": project.slug,
                "name": project.name,
                "deleted_asset_count": deleted_asset_count,
            },
        )
        delete_project(session, project)
        session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{project_id}/assets", response_model=ProjectAssetsResponse)
def project_assets_api(
    request: Request,
    project_id: str,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> ProjectAssetsResponse:
    """Return asset inventory nodes for a project.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string whose asset nodes should be returned.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable project ID and ordered asset nodes.

    Raises:
        HTTPException: If the project ID is unknown.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="project:view",
            scope_type="project",
            scope_id=project.id,
        )
        assets = list_project_assets(session, project)
        scan_labels = _scan_labels_by_asset_id(session, project)
        return ProjectAssetsResponse(
            project_id=project.id,
            assets=[
                _asset_response(asset, scan_label=scan_labels.get(asset.id)) for asset in assets
            ],
        )


@router.post(
    "/{project_id}/folders",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def folder_resolve_api(
    request: Request,
    project_id: str,
    payload: FolderResolveRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> AssetResponse:
    """Resolve a project folder path, creating missing folders.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string that owns the folder path.
        payload: Folder path request body.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable asset node metadata for the resolved folder.

    Raises:
        HTTPException: If the project is unknown or the path is invalid.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="asset:create",
            scope_type="project",
            scope_id=project.id,
        )
        try:
            folder = resolve_folder_path(session, project, payload.path)
        except ValueError as exc:
            raise _bad_request(str(exc)) from exc
        record_audit_event(
            session,
            event_type="inventory.folder.resolve",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="asset_node",
            target_id=folder.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"path": folder.path, "name": folder.name},
        )
        session.commit()
        return _asset_response(folder)


@router.post(
    "/{project_id}/scan-targets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def scan_target_create_api(
    request: Request,
    project_id: str,
    payload: ScanTargetCreateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> AssetResponse:
    """Create a scan target asset under a resolved folder path.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string that owns the scan target.
        payload: Scan target creation fields supplied as JSON.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable asset node metadata for the created scan target.

    Raises:
        HTTPException: If the project is unknown, values are invalid, or the
            target conflicts with an existing sibling/path.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="asset:create",
            scope_type="project",
            scope_id=project.id,
        )
        try:
            target = create_scan_target(
                session,
                project=project,
                folder_path=payload.folder_path,
                name=payload.name,
                target_ref=payload.target_ref,
                metadata_json=payload.metadata,
                node_type=payload.node_type,
            )
        except ValueError as exc:
            raise _bad_request(str(exc)) from exc
        except IntegrityError as exc:
            session.rollback()
            raise _asset_conflict() from exc
        record_audit_event(
            session,
            event_type="inventory.scan_target.create",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="asset_node",
            target_id=target.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "folder_path": target.parent.path if target.parent else "",
                "name": target.name,
                "node_type": str(target.node_type),
            },
        )
        session.commit()
        return _asset_response(target)


@router.patch("/{project_id}/assets/{asset_id}", response_model=AssetResponse)
def asset_update_api(
    request: Request,
    project_id: str,
    asset_id: str,
    payload: AssetUpdateRequest,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> AssetResponse:
    """Update an asset node name, parent, and nullable SLA overrides.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string that owns the asset.
        asset_id: Asset node UUID string to update.
        payload: Optional asset fields to mutate.
        actor: Authenticated request actor required for access.

    Returns:
        JSON-serializable asset node metadata after mutation.

    Raises:
        HTTPException: If the project or asset is unknown, supplied values are
            invalid, or the update conflicts with an existing sibling/path.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="asset:update",
            scope_type="project",
            scope_id=project.id,
        )
        asset = _get_project_asset_or_404(session, project, asset_id)
        changed_fields = _asset_update_changed_fields(payload)
        try:
            if "name" in payload.model_fields_set:
                if payload.name is None:
                    raise ValueError("asset node name must be non-empty")
                asset = rename_asset_node(session, asset, new_name=payload.name)
            if "parent_id" in payload.model_fields_set:
                parent = _get_parent_asset(session, project, payload.parent_id)
                asset = move_asset_node(session, asset, new_parent=parent)
            if _has_sla_update(payload):
                asset = set_asset_sla_overrides(
                    session,
                    asset,
                    sla_tracking_enabled=(
                        payload.sla_tracking_enabled
                        if "sla_tracking_enabled" in payload.model_fields_set
                        else asset.sla_tracking_enabled
                    ),
                    sla_reporting_enabled=(
                        payload.sla_reporting_enabled
                        if "sla_reporting_enabled" in payload.model_fields_set
                        else asset.sla_reporting_enabled
                    ),
                )
        except ValueError as exc:
            raise _bad_request(str(exc)) from exc
        except IntegrityError as exc:
            session.rollback()
            raise _asset_conflict() from exc
        record_audit_event(
            session,
            event_type="inventory.asset.update",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="asset_node",
            target_id=asset.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"changed_fields": changed_fields},
        )
        session.commit()
        return _asset_response(asset)


@router.delete("/{project_id}/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def asset_delete_api(
    request: Request,
    project_id: str,
    asset_id: str,
    actor: AuthenticatedActor = authenticated_actor_dependency,
) -> Response:
    """Delete an asset node and dependent inventory/finding data.

    Args:
        request: Incoming request containing application state.
        project_id: Project UUID string that owns the asset.
        asset_id: Asset node UUID string to delete.
        actor: Authenticated request actor required for access.

    Returns:
        Empty 204 response after deletion.

    Raises:
        HTTPException: If the project/asset is unknown or actor lacks permission.
    """

    session_factory = request.app.state.session_factory
    with session_factory() as session:
        project = _get_project_or_404(session, project_id)
        ensure_actor_permission(
            session,
            actor=actor,
            permission="asset:delete",
            scope_type="project",
            scope_id=project.id,
        )
        asset = _get_project_asset_or_404(session, project, asset_id)
        deleted_node_count = count_asset_subtree(session, asset)
        record_audit_event(
            session,
            event_type="inventory.asset.delete",
            actor_principal_type=actor.principal_type,
            actor_principal_id=actor.principal_id,
            actor_display=actor.display_name,
            target_type="asset_node",
            target_id=asset.id,
            project_id=project.id,
            ip_address=_client_host(request),
            user_agent=request.headers.get("user-agent"),
            metadata={
                "path": asset.path,
                "name": asset.name,
                "node_type": str(asset.node_type),
                "deleted_node_count": deleted_node_count,
            },
        )
        delete_asset_node(session, asset)
        session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _get_project_or_404(session: Session, project_id: str) -> Project:
    """Return a project or raise a 404 API error.

    Args:
        session: The database session used for lookup.
        project_id: Project UUID string to find.

    Returns:
        The matching project.

    Raises:
        HTTPException: If the project ID is unknown.
    """

    project = get_project(session, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _get_project_asset_or_404(session: Session, project: Project, asset_id: str) -> AssetNode:
    """Return a project-owned asset node or raise a 404 API error.

    Args:
        session: The database session used for lookup.
        project: Project that must own the asset.
        asset_id: Asset node UUID string to find.

    Returns:
        The matching asset node.

    Raises:
        HTTPException: If the asset is unknown or belongs to another project.
    """

    asset = session.get(AssetNode, asset_id)
    if asset is None or asset.project_id != project.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


def _get_parent_asset(
    session: Session, project: Project, parent_id: str | None
) -> AssetNode | None:
    """Return an optional project-owned parent asset node.

    Args:
        session: The database session used for lookup.
        project: Project that must own the parent asset.
        parent_id: Optional parent asset UUID string; ``None`` means root.

    Returns:
        The parent asset node, or ``None`` for project root.

    Raises:
        ValueError: If the parent ID does not resolve to a project-owned asset.
    """

    if parent_id is None:
        return None
    parent = session.get(AssetNode, parent_id)
    if parent is None or parent.project_id != project.id:
        raise ValueError("asset parent must belong to the same project")
    return parent


def _asset_update_changed_fields(payload: AssetUpdateRequest) -> list[str]:
    """Return client-supplied asset field names in stable audit order.

    Args:
        payload: Parsed asset update request.

    Returns:
        Ordered field names supplied in the patch body.
    """

    return [
        field
        for field in [
            "name",
            "parent_id",
            "sla_tracking_enabled",
            "sla_reporting_enabled",
        ]
        if field in payload.model_fields_set
    ]


def _project_update_changes(
    project: Project,
    payload: ProjectUpdateRequest,
) -> dict[str, dict[str, bool | int | str]]:
    """Return project setting changes represented as old/new values.

    Args:
        project: Existing project model.
        payload: Parsed project update request.

    Returns:
        Mapping of changed project field names to old and new values.
    """

    changes: dict[str, dict[str, bool | int | str]] = {}
    if "slug" in payload.model_fields_set and payload.slug != project.slug:
        changes["slug"] = {
            "old": project.slug,
            "new": payload.slug or "",
        }
    if "name" in payload.model_fields_set:
        normalized_name = (payload.name or "").strip()
        if normalized_name != project.name:
            changes["name"] = {
                "old": project.name,
                "new": normalized_name,
            }
    if (
        "require_peer_review_for_status_changes" in payload.model_fields_set
        and payload.require_peer_review_for_status_changes
        != project.require_peer_review_for_status_changes
    ):
        changes["require_peer_review_for_status_changes"] = {
            "old": project.require_peer_review_for_status_changes,
            "new": bool(payload.require_peer_review_for_status_changes),
        }
    if (
        "grace_period_enabled" in payload.model_fields_set
        and payload.grace_period_enabled != project.grace_period_enabled
    ):
        changes["grace_period_enabled"] = {
            "old": project.grace_period_enabled,
            "new": bool(payload.grace_period_enabled),
        }
    if (
        "grace_period_percent" in payload.model_fields_set
        and payload.grace_period_percent != project.grace_period_percent
    ):
        changes["grace_period_percent"] = {
            "old": project.grace_period_percent,
            "new": int(payload.grace_period_percent or 0),
        }
    return changes


def _has_sla_update(payload: AssetUpdateRequest) -> bool:
    """Return whether an asset update includes an SLA override field.

    Args:
        payload: Parsed asset update request.

    Returns:
        ``True`` when either nullable SLA field was supplied.
    """

    return bool(
        {"sla_tracking_enabled", "sla_reporting_enabled"}.intersection(payload.model_fields_set)
    )


def _bad_request(detail: str) -> HTTPException:
    """Build a 400 response for safe service validation messages.

    Args:
        detail: Safe error text to expose to the API caller.

    Returns:
        A configured HTTP exception.
    """

    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _project_conflict() -> HTTPException:
    """Build a 409 response for project uniqueness conflicts.

    Returns:
        A configured HTTP exception with a safe conflict message.
    """

    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Project slug or name already exists",
    )


def _asset_conflict() -> HTTPException:
    """Build a 409 response for asset uniqueness conflicts.

    Returns:
        A configured HTTP exception with a safe conflict message.
    """

    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Asset path or sibling name already exists",
    )


def _client_host(request: Request) -> str | None:
    """Return the request client host for audit logging.

    Args:
        request: Incoming request with optional client connection metadata.

    Returns:
        The client host string, or ``None`` when unavailable.
    """

    return request.client.host if request.client else None


def _project_response(project: Project) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        slug=project.slug,
        name=project.name,
        description=project.description,
        sla_tracking_enabled=project.sla_tracking_enabled,
        sla_reporting_enabled=project.sla_reporting_enabled,
        require_peer_review_for_status_changes=project.require_peer_review_for_status_changes,
        grace_period_enabled=project.grace_period_enabled,
        grace_period_percent=project.grace_period_percent,
    )


def _scan_labels_by_asset_id(session: Session, project: Project) -> dict[str, str]:
    """Return display labels for scan targets based on their latest scans.

    Args:
        session: The database session used to load scans.
        project: Project whose scan target labels should be returned.

    Returns:
        Mapping of asset node UUID to a human-readable scanner/report label.
    """

    labels: dict[str, str] = {}
    scans = session.scalars(
        select(Scan)
        .where(Scan.project_id == project.id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
    )
    for scan in scans:
        if scan.scan_target_id not in labels:
            labels[scan.scan_target_id] = _scan_label(scan)
    return labels


def _scan_label(scan: Scan) -> str:
    """Return a human-readable label for a persisted scan.

    Args:
        scan: Persisted scan whose scanner and report kind should be described.

    Returns:
        A concise display label suitable for inventory badges.
    """

    if scan.scanner_kind == ScannerKind.TRIVY and scan.report_kind in {
        "trivy-image",
        "trivy-image-json",
    }:
        return "Trivy Image Scan"
    scanner_name = scan.scanner_kind.replace("_", " ").title()
    report_name = scan.report_kind.replace("-", " ").replace("_", " ").title()
    return f"{scanner_name} {report_name}".strip()


def _asset_response(asset: AssetNode, *, scan_label: str | None = None) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        parent_id=asset.parent_id,
        path=asset.path,
        type=str(asset.node_type),
        name=asset.name,
        target_ref=asset.target_ref,
        scan_label=scan_label,
        sla_tracking_enabled=asset.sla_tracking_enabled,
        sla_reporting_enabled=asset.sla_reporting_enabled,
        sort_order=asset.sort_order,
    )
