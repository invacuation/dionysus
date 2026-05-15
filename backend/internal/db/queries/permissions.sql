-- name: ListGroupIDsForPrincipal :many
SELECT group_id
FROM group_memberships
WHERE principal_type = ? AND principal_id = ?;

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
WHERE id = ?;
