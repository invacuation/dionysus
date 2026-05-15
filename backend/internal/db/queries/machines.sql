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
WHERE token_digest = ?;

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
WHERE id = ?;

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
WHERE client_id = ?;

-- name: CreateMachineToken :one
INSERT INTO machine_tokens (
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?)
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
) VALUES (?, ?, ?, ?, ?, ?)
RETURNING
    id,
    machine_credential_id,
    token_digest,
    expires_at,
    revoked_at,
    created_at,
    updated_at;
