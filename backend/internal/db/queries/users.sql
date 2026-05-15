-- name: GetUser :one
SELECT
    id,
    username,
    display_name,
    is_active,
    created_at,
    updated_at
FROM users
WHERE id = ?;

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
WHERE users.username = ?;
