-- name: GetAppSecuritySettings :one
SELECT
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at
FROM app_security_settings
WHERE id = ?;
