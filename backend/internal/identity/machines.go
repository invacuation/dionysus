package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func VerifyMachineAccessToken(
	ctx context.Context,
	conn *sql.DB,
	rawToken string,
	now time.Time,
) (*dbgen.MachineToken, error) {
	queries := dbgen.New(conn)
	digest := security.TokenDigest(rawToken)
	token, err := queries.GetMachineTokenByDigest(ctx, digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(token.TokenDigest), []byte(digest)) != 1 {
		return nil, nil
	}

	credential, err := queries.GetMachineCredential(ctx, token.MachineCredentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !machineCredentialIsActive(credential) || token.RevokedAt.Valid {
		return nil, nil
	}

	now = now.UTC()
	if !token.ExpiresAt.UTC().After(now) {
		return nil, nil
	}
	token.ExpiresAt = token.ExpiresAt.UTC()
	return &token, nil
}

func machineCredentialIsActive(credential dbgen.MachineCredential) bool {
	return credential.IsActive && !credential.RevokedAt.Valid
}
