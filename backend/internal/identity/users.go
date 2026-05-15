package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func AuthenticateUser(ctx context.Context, conn *sql.DB, username string, password string) (*dbgen.User, error) {
	queries := dbgen.New(conn)
	row, err := queries.GetUserPasswordCredentialByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !row.IsActive || !security.VerifyPassword(password, row.PasswordHash) {
		return nil, nil
	}
	return &dbgen.User{
		ID:          row.ID,
		Username:    row.Username,
		DisplayName: row.DisplayName,
		IsActive:    row.IsActive,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

func ChangeUserPassword(ctx context.Context, conn *sql.DB, userID string, currentPassword string, newPassword string, now time.Time) error {
	queries := dbgen.New(conn)
	credential, err := queries.GetUserPasswordCredentialByUserID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCurrentPasswordIncorrect
	}
	if err != nil {
		return err
	}
	if !security.VerifyPassword(currentPassword, credential.PasswordHash) {
		return ErrCurrentPasswordIncorrect
	}
	passwordHash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = queries.UpdateUserPasswordCredential(ctx, dbgen.UpdateUserPasswordCredentialParams{
		PasswordHash: passwordHash,
		UpdatedAt:    now.UTC(),
		UserID:       userID,
	})
	return err
}

var ErrCurrentPasswordIncorrect = errors.New("current password is incorrect")
