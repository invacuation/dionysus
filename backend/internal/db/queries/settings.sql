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

-- name: CreateAppSecuritySettings :one
INSERT INTO app_security_settings (
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?)
RETURNING
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at;

-- name: UpdateAppSecuritySettings :one
UPDATE app_security_settings
SET
    force_peer_review_for_status_changes = ?,
    session_idle_timeout_minutes = ?,
    session_absolute_timeout_minutes = ?,
    updated_at = ?
WHERE id = ?
RETURNING
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at;
