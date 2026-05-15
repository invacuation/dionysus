package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func CreateSession(
	ctx context.Context,
	conn *sql.DB,
	user dbgen.User,
	now time.Time,
	idleTimeoutMinutes int,
	absoluteTimeoutMinutes int,
	userAgent *string,
	ipAddress *string,
) (string, dbgen.UserSession, error) {
	rawToken, err := security.GenerateToken()
	if err != nil {
		return "", dbgen.UserSession{}, err
	}
	now = now.UTC()
	queries := dbgen.New(conn)
	session, err := queries.CreateUserSession(ctx, dbgen.CreateUserSessionParams{
		ID:            uuid.NewString(),
		UserID:        user.ID,
		TokenDigest:   security.TokenDigest(rawToken),
		UserAgent:     nullStringFromOptional(userAgent),
		IpAddress:     nullStringFromOptional(ipAddress),
		ExpiresAt:     now.Add(time.Duration(absoluteTimeoutMinutes) * time.Minute),
		IdleExpiresAt: now.Add(time.Duration(idleTimeoutMinutes) * time.Minute),
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return "", dbgen.UserSession{}, err
	}
	return rawToken, session, nil
}

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

func nullStringFromOptional(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
