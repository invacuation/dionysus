package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
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

func CreateUser(ctx context.Context, conn *sql.DB, username string, displayName string, password string, now time.Time) (dbgen.User, error) {
	return createUserWithQueries(ctx, dbgen.New(conn), username, displayName, password, now)
}

func createUserWithQueries(ctx context.Context, queries *dbgen.Queries, username string, displayName string, password string, now time.Time) (dbgen.User, error) {
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return dbgen.User{}, err
	}
	now = now.UTC()
	user, err := queries.CreateUser(ctx, dbgen.CreateUserParams{
		ID:          uuid.NewString(),
		Username:    strings.TrimSpace(username),
		DisplayName: strings.TrimSpace(displayName),
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		return dbgen.User{}, err
	}
	_, err = queries.CreateUserPasswordCredential(ctx, dbgen.CreateUserPasswordCredentialParams{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return dbgen.User{}, err
	}
	return user, nil
}

func SetUserPassword(ctx context.Context, conn *sql.DB, userID string, newPassword string, now time.Time) error {
	passwordHash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}
	queries := dbgen.New(conn)
	_, err = queries.UpdateUserPasswordCredential(ctx, dbgen.UpdateUserPasswordCredentialParams{
		PasswordHash: passwordHash,
		UpdatedAt:    now.UTC(),
		UserID:       userID,
	})
	return err
}
