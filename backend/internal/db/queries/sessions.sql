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
WHERE token_digest = $1;

-- name: TouchUserSession :one
UPDATE user_sessions
SET
    last_seen_at = $1,
    idle_expires_at = $2,
    updated_at = $3
WHERE id = $4
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
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
    revoked_at = $1,
    updated_at = $2
WHERE id = $3
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

-- name: ListUserSessionsWithUsers :many
SELECT
    user_sessions.id,
    user_sessions.user_id,
    users.username,
    users.display_name,
    user_sessions.token_digest,
    user_sessions.user_agent,
    user_sessions.ip_address,
    user_sessions.expires_at,
    user_sessions.idle_expires_at,
    user_sessions.revoked_at,
    user_sessions.last_seen_at,
    user_sessions.created_at,
    user_sessions.updated_at
FROM user_sessions
JOIN users ON users.id = user_sessions.user_id
ORDER BY user_sessions.created_at DESC;

-- name: GetUserSessionWithUser :one
SELECT
    user_sessions.id,
    user_sessions.user_id,
    users.username,
    users.display_name,
    user_sessions.token_digest,
    user_sessions.user_agent,
    user_sessions.ip_address,
    user_sessions.expires_at,
    user_sessions.idle_expires_at,
    user_sessions.revoked_at,
    user_sessions.last_seen_at,
    user_sessions.created_at,
    user_sessions.updated_at
FROM user_sessions
JOIN users ON users.id = user_sessions.user_id
WHERE user_sessions.id = $1;
