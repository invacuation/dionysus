-- name: ListProjects :many
SELECT
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at
FROM projects
ORDER BY name, slug;

-- name: GetProject :one
SELECT
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at
FROM projects
WHERE id = ?;

-- name: GetProjectIdentityConflict :one
SELECT
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at
FROM projects
WHERE id != ? AND (slug = ? OR name = ?)
LIMIT 1;

-- name: CreateProject :one
INSERT INTO projects (
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 30, 60, 90, 180, 365, ?, ?)
RETURNING
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at;

-- name: UpdateProject :one
UPDATE projects
SET
    slug = ?,
    name = ?,
    sla_tracking_enabled = ?,
    sla_reporting_enabled = ?,
    grace_period_enabled = ?,
    grace_period_percent = ?,
    require_peer_review_for_status_changes = ?,
    updated_at = ?
WHERE id = ?
RETURNING
    id,
    slug,
    name,
    description,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    require_peer_review_for_status_changes,
    critical_sla_days,
    high_sla_days,
    medium_sla_days,
    low_sla_days,
    unknown_sla_days,
    created_at,
    updated_at;

-- name: DeleteProject :exec
DELETE FROM projects
WHERE id = ?;

-- name: CountProjectAssets :one
SELECT count(*)
FROM asset_nodes
WHERE project_id = ?;

-- name: DeleteProjectAssets :exec
DELETE FROM asset_nodes
WHERE project_id = ?;

-- name: ListProjectAssets :many
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE project_id = ?
ORDER BY path;

-- name: GetAssetNode :one
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE id = ?;

-- name: GetProjectAssetByPath :one
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE project_id = ? AND path = ?;

-- name: GetProjectTargetByParentAndTargetRef :one
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE
    project_id = sqlc.arg(project_id)
    AND node_type = sqlc.arg(node_type)
    AND target_ref = sqlc.arg(target_ref)
    AND (
        parent_id = sqlc.narg(parent_id)
        OR (parent_id IS NULL AND sqlc.narg(parent_id) IS NULL)
    )
LIMIT 1;

-- name: GetProjectAssetByParentAndName :one
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE
    project_id = sqlc.arg(project_id)
    AND name = sqlc.arg(name)
    AND (
        parent_id = sqlc.narg(parent_id)
        OR (parent_id IS NULL AND sqlc.narg(parent_id) IS NULL)
    )
LIMIT 1;

-- name: CreateAssetNode :one
INSERT INTO asset_nodes (
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at;

-- name: UpdateAssetNode :one
UPDATE asset_nodes
SET
    parent_id = ?,
    name = ?,
    path = ?,
    sla_tracking_enabled = ?,
    sla_reporting_enabled = ?,
    grace_period_enabled = ?,
    grace_period_percent = ?,
    updated_at = ?
WHERE id = ?
RETURNING
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at;

-- name: UpdateAssetPath :exec
UPDATE asset_nodes
SET
    path = ?,
    updated_at = ?
WHERE id = ?;

-- name: UpdateAssetTargetRef :exec
UPDATE asset_nodes
SET
    target_ref = ?,
    updated_at = ?
WHERE id = ?;

-- name: ListAssetSubtree :many
SELECT
    id,
    project_id,
    parent_id,
    node_type,
    name,
    path,
    target_ref,
    metadata_json,
    sla_tracking_enabled,
    sla_reporting_enabled,
    grace_period_enabled,
    grace_period_percent,
    sort_order,
    created_at,
    updated_at
FROM asset_nodes
WHERE project_id = ? AND (id = ? OR path LIKE ?)
ORDER BY path DESC;

-- name: DeleteAssetSubtree :exec
DELETE FROM asset_nodes
WHERE project_id = ? AND (id = ? OR path LIKE ?);
