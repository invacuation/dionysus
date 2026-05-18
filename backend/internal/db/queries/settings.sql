-- name: GetAppSecuritySettings :one
SELECT
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at
FROM app_security_settings
WHERE id = $1;

-- name: CreateAppSecuritySettings :one
INSERT INTO app_security_settings (
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
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
    force_peer_review_for_status_changes = $1,
    session_idle_timeout_minutes = $2,
    session_absolute_timeout_minutes = $3,
    updated_at = $4
WHERE id = $5
RETURNING
    id,
    force_peer_review_for_status_changes,
    session_idle_timeout_minutes,
    session_absolute_timeout_minutes,
    created_at,
    updated_at;
