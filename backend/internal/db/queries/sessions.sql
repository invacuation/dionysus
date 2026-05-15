-- name: GetUserSessionByTokenDigest :one
SELECT
    id,
    user_id,
    token_digest,
    user_agent,
    ip_address,
    expires_at,
    idle_expires_at,
    revoked_at,
    last_seen_at,
    created_at,
    updated_at
FROM user_sessions
WHERE token_digest = ?;

-- name: TouchUserSession :one
UPDATE user_sessions
SET
    last_seen_at = ?,
    idle_expires_at = ?,
    updated_at = ?
WHERE id = ?
RETURNING
    id,
    user_id,
    token_digest,
    user_agent,
    ip_address,
    expires_at,
    idle_expires_at,
    revoked_at,
    last_seen_at,
    created_at,
    updated_at;

-- name: CreateUserSession :one
INSERT INTO user_sessions (
    id,
    user_id,
    token_digest,
    user_agent,
    ip_address,
    expires_at,
    idle_expires_at,
    last_seen_at,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING
    id,
    user_id,
    token_digest,
    user_agent,
    ip_address,
    expires_at,
    idle_expires_at,
    revoked_at,
    last_seen_at,
    created_at,
    updated_at;

-- name: RevokeUserSession :one
UPDATE user_sessions
SET
    revoked_at = ?,
    updated_at = ?
WHERE id = ?
RETURNING
    id,
    user_id,
    token_digest,
    user_agent,
    ip_address,
    expires_at,
    idle_expires_at,
    revoked_at,
    last_seen_at,
    created_at,
    updated_at;
