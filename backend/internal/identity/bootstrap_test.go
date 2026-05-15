package identity

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

func TestBootstrapAdminFromSettingsCreatesInitialAdministrator(t *testing.T) {
	conn := openBootstrapTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	user, err := BootstrapAdminFromSettings(context.Background(), conn, config.Settings{
		BootstrapAdminUsername:    "admin",
		BootstrapAdminPassword:    "change-me-now-please",
		BootstrapAdminDisplayName: "Local Admin",
	}, now)

	if err != nil {
		t.Fatalf("BootstrapAdminFromSettings() returned error: %v", err)
	}
	if user == nil {
		t.Fatal("BootstrapAdminFromSettings() user = nil, want created user")
	}
	if user.Username != "admin" || user.DisplayName != "Local Admin" || !user.IsActive {
		t.Fatalf("created user = %#v", user)
	}
	authenticated, err := AuthenticateUser(context.Background(), conn, "admin", "change-me-now-please")
	if err != nil {
		t.Fatalf("AuthenticateUser() returned error: %v", err)
	}
	if authenticated == nil || authenticated.ID != user.ID {
		t.Fatalf("authenticated user = %#v, want bootstrap user %s", authenticated, user.ID)
	}
	check, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   user.ID,
		Permission:    AdminPermission,
	})
	if err != nil {
		t.Fatalf("CheckPermission() returned error: %v", err)
	}
	if !check.Allowed {
		t.Fatalf("admin permission allowed = false, explanation: %s", check.Explanation)
	}
}

func TestBootstrapAdminFromSettingsSkipsWhenUsersExist(t *testing.T) {
	conn := openBootstrapTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	existing, err := CreateUser(context.Background(), conn, "alice", "Alice", "correct horse battery staple", now)
	if err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	user, err := BootstrapAdminFromSettings(context.Background(), conn, config.Settings{
		BootstrapAdminUsername:    "admin",
		BootstrapAdminPassword:    "change-me-now-please",
		BootstrapAdminDisplayName: "Local Admin",
	}, now)

	if err != nil {
		t.Fatalf("BootstrapAdminFromSettings() returned error: %v", err)
	}
	if user != nil {
		t.Fatalf("BootstrapAdminFromSettings() user = %#v, want nil", user)
	}
	users, err := dbgen.New(conn).ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers() returned error: %v", err)
	}
	if len(users) != 1 || users[0].ID != existing.ID {
		t.Fatalf("users = %#v, want only existing user", users)
	}
}

func TestBootstrapAdminFromSettingsRequiresCredentialsForFreshDatabase(t *testing.T) {
	conn := openBootstrapTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	user, err := BootstrapAdminFromSettings(context.Background(), conn, config.Settings{}, now)

	if err == nil {
		t.Fatal("BootstrapAdminFromSettings() error = nil, want required credentials error")
	}
	if user != nil {
		t.Fatalf("BootstrapAdminFromSettings() user = %#v, want nil", user)
	}
	if err.Error() != "bootstrap admin username and password are required" {
		t.Fatalf("error = %q, want required credentials message", err.Error())
	}
}

func openBootstrapTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	statements := []string{
		`CREATE TABLE users (
			id VARCHAR PRIMARY KEY NOT NULL,
			username VARCHAR(150) NOT NULL UNIQUE,
			display_name VARCHAR(200) NOT NULL,
			is_active BOOLEAN NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE user_password_credentials (
			id VARCHAR PRIMARY KEY NOT NULL,
			user_id VARCHAR NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE groups (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL UNIQUE,
			display_name VARCHAR(200) NOT NULL,
			is_protected BOOLEAN NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE group_memberships (
			id VARCHAR PRIMARY KEY NOT NULL,
			group_id VARCHAR NOT NULL,
			principal_type VARCHAR(20) NOT NULL,
			principal_id VARCHAR(36) NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE permission_assignments (
			id VARCHAR PRIMARY KEY NOT NULL,
			principal_type VARCHAR(20) NOT NULL,
			principal_id VARCHAR(36) NOT NULL,
			permission VARCHAR(120) NOT NULL,
			effect VARCHAR(20) NOT NULL,
			scope_type VARCHAR(50),
			scope_id VARCHAR(36),
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("create bootstrap test table: %v", err)
		}
	}
	return conn
}
