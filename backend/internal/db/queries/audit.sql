-- name: CreateAuditLogEvent :one
INSERT INTO audit_log_events (
    id,
    event_type,
    actor_principal_type,
    actor_principal_id,
    actor_display,
    target_type,
    target_id,
    project_id,
    ip_address,
    user_agent,
    metadata_json,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING
    id,
    event_type,
    actor_principal_type,
    actor_principal_id,
    actor_display,
    target_type,
    target_id,
    project_id,
    ip_address,
    user_agent,
    metadata_json,
    created_at;

-- name: ListAuditEventTypes :many
SELECT DISTINCT event_type
FROM audit_log_events
ORDER BY event_type;

-- name: ListAuditLogEvents :many
SELECT
    id,
    event_type,
    actor_principal_type,
    actor_principal_id,
    actor_display,
    target_type,
    target_id,
    project_id,
    ip_address,
    user_agent,
    metadata_json,
    created_at
FROM audit_log_events
WHERE
    ($1 IS NULL OR event_type = $2)
    AND ($3 IS NULL OR project_id = $4)
    AND ($5 IS NULL OR target_type = $6)
    AND ($7 IS NULL OR target_id = $8)
    AND ($9 IS NULL OR created_at >= $10)
    AND ($11 IS NULL OR created_at <= $12)
ORDER BY created_at DESC
LIMIT $13;
