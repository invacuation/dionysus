-- name: GetMachineTokenByDigest :one
SELECT
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at
FROM machine_tokens
WHERE token_digest = $1;

-- name: GetMachineCredential :one
SELECT
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at
FROM machine_credentials
WHERE id = $1;

-- name: GetMachineCredentialByClientID :one
SELECT
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at
FROM machine_credentials
WHERE client_id = $1;

-- name: ListMachineCredentials :many
SELECT
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at
FROM machine_credentials
ORDER BY created_at;

-- name: CreateMachineCredential :one
INSERT INTO machine_credentials (
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at;

-- name: UpdateMachineCredentialSecret :one
UPDATE machine_credentials
SET
    client_secret_digest = $1,
    updated_at = $2
WHERE id = $3
RETURNING
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at;

-- name: RevokeMachineCredential :one
UPDATE machine_credentials
SET
    is_active = false,
    revoked_at = $1,
    updated_at = $2
WHERE id = $3
RETURNING
    id,
    name,
    client_id,
    client_secret_digest,
    is_active,
    revoked_at,
    created_at,
    updated_at;

-- name: RevokeMachineAccessTokensForCredential :exec
UPDATE machine_tokens
SET
    revoked_at = $1,
    updated_at = $2
WHERE machine_credential_id = $3 AND revoked_at IS NULL;

-- name: RevokeMachineRefreshTokensForCredential :exec
UPDATE machine_refresh_tokens
SET
    revoked_at = $1,
    updated_at = $2
WHERE machine_credential_id = $3 AND revoked_at IS NULL;

-- name: CreateMachineToken :one
INSERT INTO machine_tokens (
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at;

-- name: CreateMachineRefreshToken :one
INSERT INTO machine_refresh_tokens (
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at;

-- name: GetMachineRefreshTokenByDigest :one
SELECT
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at
FROM machine_refresh_tokens
WHERE token_digest = $1;

-- name: RevokeMachineRefreshToken :one
UPDATE machine_refresh_tokens
SET
    revoked_at = $1,
    updated_at = $2
WHERE id = $3
RETURNING
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at;
