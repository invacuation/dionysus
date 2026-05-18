package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/security"
)

type MachineClientSecretExchange struct {
	ClientID                string
	ClientSecret            string
	Now                     time.Time
	AccessExpiresInMinutes  int
	RefreshExpiresInMinutes int
}

type MachineRefreshTokenExchange struct {
	RawRefreshToken         string
	Now                     time.Time
	AccessExpiresInMinutes  int
	RefreshExpiresInMinutes int
}

type MachineTokenPair struct {
	AccessToken        string
	RefreshToken       string
	AccessTokenRecord  dbgen.MachineToken
	RefreshTokenRecord dbgen.MachineRefreshToken
}

func ExchangeMachineClientSecret(
	ctx context.Context,
	conn *sql.DB,
	exchange MachineClientSecretExchange,
) (*MachineTokenPair, error) {
	queries := dbgen.New(conn)
	credential, err := queries.GetMachineCredentialByClientID(ctx, exchange.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !verifyMachineClientSecret(credential, exchange.ClientSecret) {
		return nil, nil
	}

	now := exchange.Now.UTC()
	accessToken, accessTokenRecord, err := issueMachineAccessToken(
		ctx,
		queries,
		credential,
		now,
		exchange.AccessExpiresInMinutes,
	)
	if err != nil {
		return nil, err
	}
	refreshToken, refreshTokenRecord, err := mintMachineRefreshToken(
		ctx,
		queries,
		credential,
		now,
		exchange.RefreshExpiresInMinutes,
	)
	if err != nil {
		return nil, err
	}
	return &MachineTokenPair{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		AccessTokenRecord:  accessTokenRecord,
		RefreshTokenRecord: refreshTokenRecord,
	}, nil
}

func CreateMachineCredential(
	ctx context.Context,
	conn *sql.DB,
	name string,
	now time.Time,
) (string, dbgen.MachineCredential, error) {
	rawSecret, err := security.GenerateToken()
	if err != nil {
		return "", dbgen.MachineCredential{}, err
	}
	queries := dbgen.New(conn)
	credential, err := queries.CreateMachineCredential(ctx, dbgen.CreateMachineCredentialParams{
		ID:                 uuid.NewString(),
		Name:               name,
		ClientID:           uuid.NewString(),
		ClientSecretDigest: security.TokenDigest(rawSecret),
		IsActive:           true,
		CreatedAt:          now.UTC(),
		UpdatedAt:          now.UTC(),
	})
	if err != nil {
		return "", dbgen.MachineCredential{}, err
	}
	return rawSecret, credential, nil
}

func RegenerateMachineClientSecret(
	ctx context.Context,
	conn *sql.DB,
	credentialID string,
	now time.Time,
	revokeTokens bool,
) (string, dbgen.MachineCredential, error) {
	rawSecret, err := security.GenerateToken()
	if err != nil {
		return "", dbgen.MachineCredential{}, err
	}
	queries := dbgen.New(conn)
	now = now.UTC()
	credential, err := queries.UpdateMachineCredentialSecret(ctx, dbgen.UpdateMachineCredentialSecretParams{
		ClientSecretDigest: security.TokenDigest(rawSecret),
		UpdatedAt:          now,
		ID:                 credentialID,
	})
	if err != nil {
		return "", dbgen.MachineCredential{}, err
	}
	if revokeTokens {
		if err := revokeMachineTokensForCredential(ctx, queries, credentialID, now); err != nil {
			return "", dbgen.MachineCredential{}, err
		}
	}
	return rawSecret, credential, nil
}

func RevokeMachineCredential(
	ctx context.Context,
	conn *sql.DB,
	credentialID string,
	now time.Time,
	revokeTokens bool,
) (dbgen.MachineCredential, error) {
	queries := dbgen.New(conn)
	now = now.UTC()
	credential, err := queries.RevokeMachineCredential(ctx, dbgen.RevokeMachineCredentialParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UpdatedAt: now,
		ID:        credentialID,
	})
	if err != nil {
		return dbgen.MachineCredential{}, err
	}
	if revokeTokens {
		if err := revokeMachineTokensForCredential(ctx, queries, credentialID, now); err != nil {
			return dbgen.MachineCredential{}, err
		}
	}
	return credential, nil
}

func revokeMachineTokensForCredential(ctx context.Context, queries *dbgen.Queries, credentialID string, now time.Time) error {
	if err := queries.RevokeMachineAccessTokensForCredential(ctx, dbgen.RevokeMachineAccessTokensForCredentialParams{
		RevokedAt:           sql.NullTime{Time: now, Valid: true},
		UpdatedAt:           now,
		MachineCredentialID: credentialID,
	}); err != nil {
		return err
	}
	return queries.RevokeMachineRefreshTokensForCredential(ctx, dbgen.RevokeMachineRefreshTokensForCredentialParams{
		RevokedAt:           sql.NullTime{Time: now, Valid: true},
		UpdatedAt:           now,
		MachineCredentialID: credentialID,
	})
}

func RefreshMachineToken(
	ctx context.Context,
	conn *sql.DB,
	exchange MachineRefreshTokenExchange,
) (*MachineTokenPair, error) {
	queries := dbgen.New(conn)
	digest := security.TokenDigest(exchange.RawRefreshToken)
	refreshTokenRecord, err := queries.GetMachineRefreshTokenByDigest(ctx, digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(refreshTokenRecord.TokenDigest), []byte(digest)) != 1 {
		return nil, nil
	}

	now := exchange.Now.UTC()
	if refreshTokenRecord.RevokedAt.Valid || !refreshTokenRecord.ExpiresAt.UTC().After(now) {
		return nil, nil
	}

	credential, err := queries.GetMachineCredential(ctx, refreshTokenRecord.MachineCredentialID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !machineCredentialIsActive(credential) {
		return nil, nil
	}

	if _, err := queries.RevokeMachineRefreshToken(ctx, dbgen.RevokeMachineRefreshTokenParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UpdatedAt: now,
		ID:        refreshTokenRecord.ID,
	}); err != nil {
		return nil, err
	}

	accessToken, accessTokenRecord, err := issueMachineAccessToken(
		ctx,
		queries,
		credential,
		now,
		exchange.AccessExpiresInMinutes,
	)
	if err != nil {
		return nil, err
	}
	refreshToken, newRefreshTokenRecord, err := mintMachineRefreshToken(
		ctx,
		queries,
		credential,
		now,
		exchange.RefreshExpiresInMinutes,
	)
	if err != nil {
		return nil, err
	}
	return &MachineTokenPair{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		AccessTokenRecord:  accessTokenRecord,
		RefreshTokenRecord: newRefreshTokenRecord,
	}, nil
}

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

func verifyMachineClientSecret(credential dbgen.MachineCredential, rawSecret string) bool {
	if !machineCredentialIsActive(credential) {
		return false
	}
	digest := security.TokenDigest(rawSecret)
	return subtle.ConstantTimeCompare([]byte(credential.ClientSecretDigest), []byte(digest)) == 1
}

func issueMachineAccessToken(
	ctx context.Context,
	queries *dbgen.Queries,
	credential dbgen.MachineCredential,
	now time.Time,
	expiresInMinutes int,
) (string, dbgen.MachineToken, error) {
	rawToken, err := security.GenerateToken()
	if err != nil {
		return "", dbgen.MachineToken{}, err
	}
	token, err := queries.CreateMachineToken(ctx, dbgen.CreateMachineTokenParams{
		ID:                  uuid.NewString(),
		MachineCredentialID: credential.ID,
		TokenDigest:         security.TokenDigest(rawToken),
		ExpiresAt:           now.Add(time.Duration(expiresInMinutes) * time.Minute),
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		return "", dbgen.MachineToken{}, err
	}
	return rawToken, token, nil
}

func mintMachineRefreshToken(
	ctx context.Context,
	queries *dbgen.Queries,
	credential dbgen.MachineCredential,
	now time.Time,
	expiresInMinutes int,
) (string, dbgen.MachineRefreshToken, error) {
	rawToken, err := security.GenerateToken()
	if err != nil {
		return "", dbgen.MachineRefreshToken{}, err
	}
	token, err := queries.CreateMachineRefreshToken(ctx, dbgen.CreateMachineRefreshTokenParams{
		ID:                  uuid.NewString(),
		MachineCredentialID: credential.ID,
		TokenDigest:         security.TokenDigest(rawToken),
		ExpiresAt:           now.Add(time.Duration(expiresInMinutes) * time.Minute),
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		return "", dbgen.MachineRefreshToken{}, err
	}
	return rawToken, token, nil
}
