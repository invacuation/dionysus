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
WHERE id = $1;

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
WHERE id != $1 AND (slug = $2 OR name = $3)
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
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 30, 60, 90, 180, 365, $10, $11)
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
    slug = $1,
    name = $2,
    sla_tracking_enabled = $3,
    sla_reporting_enabled = $4,
    grace_period_enabled = $5,
    grace_period_percent = $6,
    require_peer_review_for_status_changes = $7,
    updated_at = $8
WHERE id = $9
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
WHERE id = $1;

-- name: CountProjectAssets :one
SELECT count(*)
FROM asset_nodes
WHERE project_id = $1;

-- name: DeleteProjectAssets :exec
DELETE FROM asset_nodes
WHERE project_id = $1;

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
WHERE project_id = $1
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
WHERE id = $1;

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
WHERE project_id = $1 AND path = $2;

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
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
    parent_id = $1,
    name = $2,
    path = $3,
    sla_tracking_enabled = $4,
    sla_reporting_enabled = $5,
    grace_period_enabled = $6,
    grace_period_percent = $7,
    updated_at = $8
WHERE id = $9
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
    path = $1,
    updated_at = $2
WHERE id = $3;

-- name: UpdateAssetTargetRef :exec
UPDATE asset_nodes
SET
    target_ref = $1,
    updated_at = $2
WHERE id = $3;

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
WHERE project_id = $1 AND (id = $2 OR path LIKE $3)
ORDER BY path DESC;

-- name: DeleteAssetSubtree :exec
DELETE FROM asset_nodes
WHERE project_id = $1 AND (id = $2 OR path LIKE $3);
