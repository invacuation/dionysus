package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

const (
	adminGroupName        = "administrators"
	adminGroupDisplayName = "Administrators"
)

func BootstrapAdminFromSettings(ctx context.Context, conn *sql.DB, settings config.Settings, now time.Time) (*dbgen.User, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	queries := dbgen.New(tx)
	existingUsers, err := queries.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	if len(existingUsers) > 0 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if settings.BootstrapAdminUsername == "" || settings.BootstrapAdminPassword == "" {
		return nil, errors.New("bootstrap admin username and password are required")
	}
	displayName := settings.BootstrapAdminDisplayName
	if displayName == "" {
		displayName = settings.BootstrapAdminUsername
	}

	user, err := createUserWithQueries(ctx, queries, settings.BootstrapAdminUsername, displayName, settings.BootstrapAdminPassword, now)
	if err != nil {
		return nil, err
	}
	group, err := getOrCreateAdminGroup(ctx, queries, now)
	if err != nil {
		return nil, err
	}
	if err := ensureAdminMembership(ctx, queries, group.ID, user.ID, now); err != nil {
		return nil, err
	}
	if err := ensureAdminPermission(ctx, queries, group.ID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &user, nil
}

func getOrCreateAdminGroup(ctx context.Context, queries *dbgen.Queries, now time.Time) (dbgen.Group, error) {
	group, err := queries.GetGroupByName(ctx, adminGroupName)
	if errors.Is(err, sql.ErrNoRows) {
		return queries.CreateGroup(ctx, dbgen.CreateGroupParams{
			ID:          uuid.NewString(),
			Name:        adminGroupName,
			DisplayName: adminGroupDisplayName,
			IsProtected: true,
			CreatedAt:   now.UTC(),
			UpdatedAt:   now.UTC(),
		})
	}
	if err != nil {
		return dbgen.Group{}, err
	}
	return queries.UpdateGroup(ctx, dbgen.UpdateGroupParams{
		DisplayName: adminGroupDisplayName,
		IsProtected: true,
		UpdatedAt:   now.UTC(),
		ID:          group.ID,
	})
}

func ensureAdminMembership(ctx context.Context, queries *dbgen.Queries, groupID string, userID string, now time.Time) error {
	_, err := queries.GetGroupMembership(ctx, dbgen.GetGroupMembershipParams{
		GroupID:       groupID,
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   userID,
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = queries.CreateGroupMembership(ctx, dbgen.CreateGroupMembershipParams{
		ID:            uuid.NewString(),
		GroupID:       groupID,
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   userID,
		CreatedAt:     now.UTC(),
		UpdatedAt:     now.UTC(),
	})
	return err
}

func ensureAdminPermission(ctx context.Context, queries *dbgen.Queries, groupID string, now time.Time) error {
	_, err := queries.GetPermissionAssignment(ctx, dbgen.GetPermissionAssignmentParams{
		PrincipalType: PrincipalTypeGroup,
		PrincipalID:   groupID,
		Permission:    AdminPermission,
		Effect:        PermissionEffectAllow,
		ScopeType:     sql.NullString{},
		ScopeID:       sql.NullString{},
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = queries.CreatePermissionAssignment(ctx, dbgen.CreatePermissionAssignmentParams{
		ID:            uuid.NewString(),
		PrincipalType: PrincipalTypeGroup,
		PrincipalID:   groupID,
		Permission:    AdminPermission,
		Effect:        PermissionEffectAllow,
		ScopeType:     sql.NullString{},
		ScopeID:       sql.NullString{},
		CreatedAt:     now.UTC(),
		UpdatedAt:     now.UTC(),
	})
	return err
}
