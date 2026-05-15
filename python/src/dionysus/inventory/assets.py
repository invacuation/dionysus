"""Asset inventory tree services."""

from collections.abc import Mapping
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from dionysus.models.inventory import AssetNode, AssetNodeType, Project

_TARGET_NODE_TYPES = {
    AssetNodeType.BRANCH,
    AssetNodeType.RELEASE,
    AssetNodeType.TAG,
    AssetNodeType.CONTAINER_IMAGE,
    AssetNodeType.MANIFEST,
    AssetNodeType.FILE,
    AssetNodeType.SCAN_TARGET,
    AssetNodeType.OTHER,
}


def normalize_folder_path(path: str) -> str:
    """Normalize a public folder path to slash-delimited relative form.

    Args:
        path: The folder path supplied by a caller.

    Returns:
        The normalized path with whitespace trimmed around each segment.

    Raises:
        ValueError: If the path is empty or contains unsafe/blank segments.
    """

    if not path.strip():
        raise ValueError("folder path must be non-empty")

    segments = []
    for raw_segment in path.split("/"):
        segment = raw_segment.strip()
        if segment == "":
            raise ValueError("folder path must not contain empty segments")
        if segment in {".", ".."}:
            raise ValueError("folder path must not contain relative segments")
        segments.append(segment)
    return "/".join(segments)


def resolve_folder_path(session: Session, project: Project, path: str) -> AssetNode:
    """Return the folder node for a path, creating missing folders.

    Args:
        session: The database session used for lookup and creation.
        project: The project that owns the folder path.
        path: Public slash-delimited folder path relative to the project.

    Returns:
        The existing or newly-created folder node for the final path segment.

    Raises:
        ValueError: If the folder path is invalid.
    """

    normalized_path = normalize_folder_path(path)
    if project.id is None:
        session.add(project)
        session.flush()

    parent: AssetNode | None = None
    current_path = ""
    for segment in normalized_path.split("/"):
        current_path = _child_path(parent, segment) if parent is not None else segment
        folder = session.scalar(
            select(AssetNode).where(
                AssetNode.project_id == project.id,
                AssetNode.path == current_path,
            )
        )
        if folder is not None and folder.node_type != AssetNodeType.FOLDER:
            raise ValueError("folder path conflicts with existing asset node")
        if folder is None:
            folder = AssetNode(
                project=project,
                parent=parent,
                node_type=AssetNodeType.FOLDER,
                name=segment,
                path=current_path,
            )
            session.add(folder)
            session.flush()
        parent = folder
    if parent is None:
        raise ValueError("folder path must be non-empty")
    return parent


def create_asset_node(
    session: Session,
    *,
    project: Project,
    parent: AssetNode | None,
    node_type: AssetNodeType | str,
    name: str,
    target_ref: str | None = None,
    metadata_json: Mapping[str, Any] | None = None,
    sla_tracking_enabled: bool | None = None,
    sla_reporting_enabled: bool | None = None,
    grace_period_enabled: bool | None = None,
    grace_period_percent: int | None = None,
    sort_order: int = 0,
) -> AssetNode:
    """Create and flush an asset node under an optional parent.

    Args:
        session: The database session used to persist the node.
        project: The project that owns the asset.
        parent: Optional parent folder or asset node.
        node_type: The inventory node type to create.
        name: The user-facing node name.
        target_ref: Optional scanner-facing technical reference.
        metadata_json: Optional JSON-compatible metadata.
        sla_tracking_enabled: Optional per-node SLA tracking override.
        sla_reporting_enabled: Optional per-node SLA reporting override.
        grace_period_enabled: Optional per-node grace period override.
        grace_period_percent: Optional per-node grace period percentage override.
        sort_order: Stable sibling ordering hint.

    Returns:
        The flushed asset node.

    Raises:
        ValueError: If the name, type, or parent/project combination is invalid.
    """

    validated_name = _validate_node_name(name)
    validated_type = _validate_node_type(node_type)
    _validate_parent_project(project, parent)
    _validate_grace_period_percent(grace_period_percent)

    node = AssetNode(
        project=project,
        parent=parent,
        node_type=validated_type,
        name=validated_name,
        path=_child_path(parent, validated_name),
        target_ref=target_ref,
        metadata_json=dict(metadata_json or {}),
        sla_tracking_enabled=sla_tracking_enabled,
        sla_reporting_enabled=sla_reporting_enabled,
        grace_period_enabled=grace_period_enabled,
        grace_period_percent=grace_period_percent,
        sort_order=sort_order,
    )
    session.add(node)
    session.flush()
    return node


def create_scan_target(
    session: Session,
    *,
    project: Project,
    folder_path: str,
    name: str,
    target_ref: str,
    metadata_json: Mapping[str, Any] | None = None,
    node_type: AssetNodeType | str = AssetNodeType.SCAN_TARGET,
) -> AssetNode:
    """Create a named scan target under a resolved folder path.

    Args:
        session: The database session used to persist the target.
        project: The project that owns the target.
        folder_path: Public folder path under which to place the target.
        name: The user-facing target name.
        target_ref: The scanner-facing target reference.
        metadata_json: Optional JSON-compatible import/scanner metadata.
        node_type: The target-like node type to create.

    Returns:
        The flushed target node.

    Raises:
        ValueError: If the node type is not valid for scan target creation.
    """

    validated_type = _validate_node_type(node_type)
    if validated_type not in _TARGET_NODE_TYPES:
        raise ValueError("scan target node type must be target-like")

    parent = resolve_folder_path(session, project, folder_path)
    return create_asset_node(
        session,
        project=project,
        parent=parent,
        node_type=validated_type,
        name=name,
        target_ref=target_ref,
        metadata_json=metadata_json,
    )


def create_or_reuse_scan_target(
    session: Session,
    *,
    project: Project,
    folder: AssetNode | None,
    name: str,
    target_ref: str,
    metadata_json: Mapping[str, Any] | None = None,
    node_type: AssetNodeType | str = AssetNodeType.SCAN_TARGET,
) -> AssetNode:
    """Return a matching scanned asset under a folder, creating it when needed.

    Args:
        session: The database session used to persist the target.
        project: The project that owns the target.
    folder: Existing folder node that should contain the target, or ``None`` for
        the project root.
        name: The user-facing asset name.
        target_ref: The scanner-facing target reference.
        metadata_json: Optional JSON-compatible import/scanner metadata.
        node_type: The target-like node type to create when no match exists.

    Returns:
        The existing or newly-created target node.

    Raises:
        ValueError: If the folder/type/details are invalid or conflict with an
            incompatible existing sibling.
    """

    validated_type = _validate_node_type(node_type)
    if validated_type not in _TARGET_NODE_TYPES:
        raise ValueError("scan target node type must be target-like")
    _validate_parent_project(project, folder)
    if folder is not None and folder.node_type != AssetNodeType.FOLDER:
        raise ValueError("import folder must be a folder")

    validated_name = _validate_node_name(name)
    normalized_target_ref = target_ref.strip()
    if not normalized_target_ref:
        raise ValueError("asset target_ref must be non-empty")

    existing_by_ref = session.scalar(
        select(AssetNode).where(
            AssetNode.project_id == project.id,
            AssetNode.parent_id == (folder.id if folder is not None else None),
            AssetNode.node_type == validated_type,
            AssetNode.target_ref == normalized_target_ref,
        )
    )
    if existing_by_ref is not None:
        return existing_by_ref

    existing_by_name = session.scalar(
        select(AssetNode).where(
            AssetNode.project_id == project.id,
            AssetNode.parent_id == (folder.id if folder is not None else None),
            AssetNode.name == validated_name,
        )
    )
    if existing_by_name is not None:
        if existing_by_name.node_type != validated_type:
            raise ValueError("asset name conflicts with existing folder item")
        if existing_by_name.target_ref and existing_by_name.target_ref != normalized_target_ref:
            raise ValueError("asset name conflicts with existing target reference")
        if not existing_by_name.target_ref:
            existing_by_name.target_ref = normalized_target_ref
            session.flush()
        return existing_by_name

    return create_asset_node(
        session,
        project=project,
        parent=folder,
        node_type=validated_type,
        name=validated_name,
        target_ref=normalized_target_ref,
        metadata_json=metadata_json,
    )


def list_project_assets(session: Session, project: Project) -> list[AssetNode]:
    """Return project asset nodes sorted by path.

    Args:
        session: The database session used for lookup.
        project: The project whose assets should be returned.

    Returns:
        All project asset nodes ordered by path.
    """

    return list(
        session.scalars(
            select(AssetNode).where(AssetNode.project_id == project.id).order_by(AssetNode.path)
        )
    )


def count_project_assets(session: Session, project: Project) -> int:
    """Return the number of asset nodes owned by a project.

    Args:
        session: The database session used for lookup.
        project: Project whose assets should be counted.

    Returns:
        Count of asset nodes owned by the project.
    """

    return int(session.scalar(select(func.count()).where(AssetNode.project_id == project.id)) or 0)


def count_asset_subtree(session: Session, node: AssetNode) -> int:
    """Return the number of asset nodes in a node's subtree, including itself.

    Args:
        session: The database session used for lookup.
        node: Root asset node of the subtree.

    Returns:
        Count of the node and its descendants.
    """

    return int(
        session.scalar(
            select(func.count()).where(
                AssetNode.project_id == node.project_id,
                or_(AssetNode.id == node.id, AssetNode.path.like(f"{node.path}/%")),
            )
        )
        or 0
    )


def delete_asset_node(session: Session, node: AssetNode) -> None:
    """Delete an asset node and its ORM-cascaded descendants/dependents.

    Args:
        session: The database session used to delete the node.
        node: Asset node to remove.
    """

    session.delete(node)
    session.flush()


def move_asset_node(
    session: Session,
    node: AssetNode,
    *,
    new_parent: AssetNode | None,
) -> AssetNode:
    """Move an asset node and recompute descendant paths.

    Args:
        session: The database session used to persist path changes.
        node: The asset node to move.
        new_parent: The new parent, or ``None`` for project root.

    Returns:
        The moved node.

    Raises:
        ValueError: If the move would create a cycle or cross projects.
    """

    if new_parent is node:
        raise ValueError("cannot move an asset node under itself")
    _validate_parent_project(node.project, new_parent)
    if new_parent is not None and _is_descendant_path(new_parent.path, node.path):
        raise ValueError("cannot move an asset node under one of its descendants")

    old_path = node.path
    new_path = _child_path(new_parent, node.name)
    descendants = _descendants_for_path(session, node)
    node.parent = new_parent
    node.path = new_path
    _recompute_descendant_paths(descendants, old_path, new_path)
    session.flush()
    return node


def rename_asset_node(session: Session, node: AssetNode, *, new_name: str) -> AssetNode:
    """Rename an asset node and recompute descendant paths.

    Args:
        session: The database session used to persist path changes.
        node: The asset node to rename.
        new_name: The new user-facing sibling name.

    Returns:
        The renamed node.

    Raises:
        ValueError: If the name is invalid.
    """

    validated_name = _validate_node_name(new_name)
    old_path = node.path
    new_path = _child_path(node.parent, validated_name)
    descendants = _descendants_for_path(session, node)
    node.name = validated_name
    node.path = new_path
    _recompute_descendant_paths(descendants, old_path, new_path)
    session.flush()
    return node


def set_asset_sla_overrides(
    session: Session,
    node: AssetNode,
    *,
    sla_tracking_enabled: bool | None = None,
    sla_reporting_enabled: bool | None = None,
    grace_period_enabled: bool | None = None,
    grace_period_percent: int | None = None,
) -> AssetNode:
    """Set nullable per-asset SLA overrides.

    Args:
        session: The database session used to persist the overrides.
        node: The asset node receiving overrides.
        sla_tracking_enabled: Optional tracking override.
        sla_reporting_enabled: Optional reporting override.
        grace_period_enabled: Optional grace period override.
        grace_period_percent: Optional grace period percentage override.

    Returns:
        The updated asset node.
    """

    _validate_grace_period_percent(grace_period_percent)
    node.sla_tracking_enabled = sla_tracking_enabled
    node.sla_reporting_enabled = sla_reporting_enabled
    node.grace_period_enabled = grace_period_enabled
    node.grace_period_percent = grace_period_percent
    session.flush()
    return node


def _validate_node_type(node_type: AssetNodeType | str) -> AssetNodeType:
    try:
        return AssetNodeType(node_type)
    except ValueError as exc:
        raise ValueError("asset node type must be valid") from exc


def _validate_node_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise ValueError("asset node name must be non-empty")
    if "/" in normalized:
        raise ValueError("asset node name must not contain path separators")
    if normalized in {".", ".."}:
        raise ValueError("asset node name must not be a relative segment")
    return normalized


def _validate_parent_project(project: Project, parent: AssetNode | None) -> None:
    if parent is not None and parent.project_id != project.id:
        raise ValueError("asset parent must belong to the same project")


def _validate_grace_period_percent(grace_period_percent: int | None) -> None:
    if grace_period_percent is not None and grace_period_percent <= 0:
        raise ValueError("grace_period_percent must be a positive integer")


def _child_path(parent: AssetNode | None, name: str) -> str:
    if parent is None:
        return name
    return f"{parent.path}/{name}"


def _descendants_for_path(session: Session, node: AssetNode) -> list[AssetNode]:
    return [
        candidate
        for candidate in session.scalars(
            select(AssetNode)
            .where(AssetNode.project_id == node.project_id)
            .order_by(AssetNode.path)
        )
        if _is_descendant_path(candidate.path, node.path)
    ]


def _recompute_descendant_paths(
    descendants: list[AssetNode],
    old_path: str,
    new_path: str,
) -> None:
    for descendant in descendants:
        descendant.path = f"{new_path}{descendant.path.removeprefix(old_path)}"


def _is_descendant_path(candidate_path: str, ancestor_path: str) -> bool:
    return candidate_path.startswith(f"{ancestor_path}/")
