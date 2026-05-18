-- name: ListGroupIDsForPrincipal :many
SELECT group_id
FROM group_memberships
WHERE principal_type = $1 AND principal_id = $2;

-- name: ListMatchingAssignmentsForPrincipal :many
SELECT
    id,
    principal_type,
    principal_id,
    permission,
    effect,
    scope_type,
    scope_id,
    created_at,
    updated_at
FROM permission_assignments
WHERE
    principal_type = sqlc.arg(principal_type)
    AND principal_id = sqlc.arg(principal_id)
    AND permission = sqlc.arg(permission)
    AND (
        scope_type = sqlc.narg(scope_type)
        OR (scope_type IS NULL AND sqlc.narg(scope_type) IS NULL)
    )
    AND (
        scope_id = sqlc.narg(scope_id)
        OR (scope_id IS NULL AND sqlc.narg(scope_id) IS NULL)
    );

-- name: GetGroupName :one
SELECT name
FROM groups
WHERE id = $1;

-- name: GetGroup :one
SELECT
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at
FROM groups
WHERE id = $1;

-- name: GetGroupByName :one
SELECT
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at
FROM groups
WHERE name = $1;

-- name: UpdateGroup :one
UPDATE groups
SET
    display_name = $1,
    is_protected = $2,
    updated_at = $3
WHERE id = $4
RETURNING
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at;

-- name: CreateGroup :one
INSERT INTO groups (
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at;

-- name: ListGroups :many
SELECT
    id,
    name,
    display_name,
    is_protected,
    created_at,
    updated_at
FROM groups
ORDER BY name;

-- name: ListGroupMemberships :many
SELECT
    id,
    group_id,
    principal_type,
    principal_id,
    created_at,
    updated_at
FROM group_memberships
ORDER BY created_at;

-- name: ListPermissionAssignments :many
SELECT
    id,
    principal_type,
    principal_id,
    permission,
    effect,
    scope_type,
    scope_id,
    created_at,
    updated_at
FROM permission_assignments
ORDER BY created_at;

-- name: GetGroupMembership :one
SELECT
    id,
    group_id,
    principal_type,
    principal_id,
    created_at,
    updated_at
FROM group_memberships
WHERE group_id = $1 AND principal_type = $2 AND principal_id = $3;

-- name: CreateGroupMembership :one
INSERT INTO group_memberships (
    id,
    group_id,
    principal_type,
    principal_id,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id,
    group_id,
    principal_type,
    principal_id,
    created_at,
    updated_at;

-- name: GetPermissionAssignment :one
SELECT
    id,
    principal_type,
    principal_id,
    permission,
    effect,
    scope_type,
    scope_id,
    created_at,
    updated_at
FROM permission_assignments
WHERE
    principal_type = sqlc.arg(principal_type)
    AND principal_id = sqlc.arg(principal_id)
    AND permission = sqlc.arg(permission)
    AND effect = sqlc.arg(effect)
    AND (
        scope_type = sqlc.narg(scope_type)
        OR (scope_type IS NULL AND sqlc.narg(scope_type) IS NULL)
    )
    AND (
        scope_id = sqlc.narg(scope_id)
        OR (scope_id IS NULL AND sqlc.narg(scope_id) IS NULL)
    );

-- name: CreatePermissionAssignment :one
INSERT INTO permission_assignments (
    id,
    principal_type,
    principal_id,
    permission,
    effect,
    scope_type,
    scope_id,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING
    id,
    principal_type,
    principal_id,
    permission,
    effect,
    scope_type,
    scope_id,
    created_at,
    updated_at;
