package identity

import (
	"context"
	"database/sql"
	"errors"

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
