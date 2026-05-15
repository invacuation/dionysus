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
