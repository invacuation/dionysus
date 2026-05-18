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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    (? IS NULL OR event_type = ?)
    AND (? IS NULL OR project_id = ?)
    AND (? IS NULL OR target_type = ?)
    AND (? IS NULL OR target_id = ?)
    AND (? IS NULL OR created_at >= ?)
    AND (? IS NULL OR created_at <= ?)
ORDER BY created_at DESC
LIMIT ?;
