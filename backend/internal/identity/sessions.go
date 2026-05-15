package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func GetActiveSession(
	ctx context.Context,
	conn *sql.DB,
	rawToken string,
	now time.Time,
	idleTimeoutMinutes int,
) (*dbgen.UserSession, error) {
	queries := dbgen.New(conn)
	session, err := queries.GetUserSessionByTokenDigest(ctx, security.TokenDigest(rawToken))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if session.RevokedAt.Valid {
		return nil, nil
	}

	now = now.UTC()
	expiresAt := session.ExpiresAt.UTC()
	idleExpiresAt := session.IdleExpiresAt.UTC()
	if !expiresAt.After(now) || !idleExpiresAt.After(now) {
		return nil, nil
	}

	nextIdleExpiry := now.Add(time.Duration(idleTimeoutMinutes) * time.Minute)
	if nextIdleExpiry.After(expiresAt) {
		nextIdleExpiry = expiresAt
	}

	touched, err := queries.TouchUserSession(ctx, dbgen.TouchUserSessionParams{
		LastSeenAt:    now,
		IdleExpiresAt: nextIdleExpiry,
		UpdatedAt:     now,
		ID:            session.ID,
	})
	if err != nil {
		return nil, err
	}
	return &touched, nil
}
