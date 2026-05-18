-- name: GetUser :one
SELECT
    id,
    username,
    display_name,
    is_active,
    created_at,
    updated_at
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT
    id,
    username,
    display_name,
    is_active,
    created_at,
    updated_at
FROM users
ORDER BY username;

-- name: GetUserPasswordCredentialByUsername :one
SELECT
    users.id,
    users.username,
    users.display_name,
    users.is_active,
    users.created_at,
    users.updated_at,
    user_password_credentials.password_hash
FROM users
JOIN user_password_credentials ON user_password_credentials.user_id = users.id
WHERE users.username = $1;

-- name: GetUserPasswordCredentialByUserID :one
SELECT
    id,
    user_id,
    password_hash,
    created_at,
    updated_at
FROM user_password_credentials
WHERE user_id = $1;

-- name: UpdateUserPasswordCredential :one
UPDATE user_password_credentials
SET
    password_hash = $1,
    updated_at = $2
WHERE user_id = $3
RETURNING
    id,
    user_id,
    password_hash,
    created_at,
    updated_at;

-- name: CreateUser :one
INSERT INTO users (
    id,
    username,
    display_name,
    is_active,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id,
    username,
    display_name,
    is_active,
    created_at,
    updated_at;

-- name: CreateUserPasswordCredential :one
INSERT INTO user_password_credentials (
    id,
    user_id,
    password_hash,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING
    id,
    user_id,
    password_hash,
    created_at,
    updated_at;
