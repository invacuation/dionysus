package identity_test

import (
	"context"
	"database/sql"
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db"
)

func TestCheckPermissionAllowsDirectGrant(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-1",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		Effect:        PermissionEffectAllow,
		ScopeType:     sql.NullString{String: "project", Valid: true},
		ScopeID:       sql.NullString{String: "project-1", Valid: true},
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	check, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		ScopeType:     stringPtr("project"),
		ScopeID:       stringPtr("project-1"),
	})
	if err != nil {
		t.Fatalf("CheckPermission() returned error: %v", err)
	}
	if !check.Allowed {
		t.Fatalf("Allowed = false, explanation: %s", check.Explanation)
	}
	if !strings.Contains(check.Explanation, "direct allow") {
		t.Fatalf("Explanation = %q, want direct allow", check.Explanation)
	}
}

func TestCheckPermissionDenyOverridesGroupGrant(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertGroup(t, conn, groupFixture{
		ID:          "group-1",
		Name:        "developers",
		DisplayName: "Developers",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	insertGroupMembership(t, conn, groupMembershipFixture{
		ID:            "membership-1",
		GroupID:       "group-1",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-1",
		PrincipalType: PrincipalTypeGroup,
		PrincipalID:   "group-1",
		Permission:    "project:view",
		Effect:        PermissionEffectAllow,
		ScopeType:     sql.NullString{String: "project", Valid: true},
		ScopeID:       sql.NullString{String: "dolor", Valid: true},
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-2",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		Effect:        PermissionEffectDeny,
		ScopeType:     sql.NullString{String: "project", Valid: true},
		ScopeID:       sql.NullString{String: "dolor", Valid: true},
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	check, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		ScopeType:     stringPtr("project"),
		ScopeID:       stringPtr("dolor"),
	})
	if err != nil {
		t.Fatalf("CheckPermission() returned error: %v", err)
	}
	if check.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !check.Denied {
		t.Fatal("Denied = false, want true")
	}
	if !strings.Contains(check.Explanation, "explicit deny") || !strings.Contains(check.Explanation, "developers") {
		t.Fatalf("Explanation = %q, want explicit deny with group context", check.Explanation)
	}
}

func TestCheckPermissionAllowsNestedGroupGrant(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertGroup(t, conn, groupFixture{ID: "group-1", Name: "developers", DisplayName: "Developers", CreatedAt: now, UpdatedAt: now})
	insertGroup(t, conn, groupFixture{ID: "group-2", Name: "admins", DisplayName: "Admins", CreatedAt: now, UpdatedAt: now})
	insertGroupMembership(t, conn, groupMembershipFixture{ID: "membership-1", GroupID: "group-1", PrincipalType: PrincipalTypeUser, PrincipalID: "user-1", CreatedAt: now, UpdatedAt: now})
	insertGroupMembership(t, conn, groupMembershipFixture{ID: "membership-2", GroupID: "group-2", PrincipalType: PrincipalTypeGroup, PrincipalID: "group-1", CreatedAt: now, UpdatedAt: now})
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-1",
		PrincipalType: PrincipalTypeGroup,
		PrincipalID:   "group-2",
		Permission:    "project:update",
		Effect:        PermissionEffectAllow,
		ScopeType:     sql.NullString{String: "project", Valid: true},
		ScopeID:       sql.NullString{String: "project-1", Valid: true},
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	check, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:update",
		ScopeType:     stringPtr("project"),
		ScopeID:       stringPtr("project-1"),
	})
	if err != nil {
		t.Fatalf("CheckPermission() returned error: %v", err)
	}
	if !check.Allowed {
		t.Fatalf("Allowed = false, explanation: %s", check.Explanation)
	}
	if !strings.Contains(check.Explanation, "admins") {
		t.Fatalf("Explanation = %q, want admins", check.Explanation)
	}
}

func TestCheckPermissionRejectsHalfScopedRequest(t *testing.T) {
	conn := openPermissionTestDB(t)

	_, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		ScopeType:     stringPtr("project"),
	})
	if err == nil {
		t.Fatal("CheckPermission() error = nil, want scope error")
	}
	if !strings.Contains(err.Error(), "scope_type and scope_id must both be set or both be nil") {
		t.Fatalf("error = %q, want scope pair message", err.Error())
	}
}

func TestCheckPermissionReturnsNoGrantWithGroupContext(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertGroup(t, conn, groupFixture{ID: "group-1", Name: "developers", DisplayName: "Developers", CreatedAt: now, UpdatedAt: now})
	insertGroupMembership(t, conn, groupMembershipFixture{ID: "membership-1", GroupID: "group-1", PrincipalType: PrincipalTypeUser, PrincipalID: "user-1", CreatedAt: now, UpdatedAt: now})

	check, err := CheckPermission(context.Background(), conn, PermissionRequest{
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		ScopeType:     stringPtr("project"),
		ScopeID:       stringPtr("project-1"),
	})
	if err != nil {
		t.Fatalf("CheckPermission() returned error: %v", err)
	}
	if check.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if !strings.Contains(check.Explanation, "no matching grant") || !strings.Contains(check.Explanation, "developers") {
		t.Fatalf("Explanation = %q, want no grant with group context", check.Explanation)
	}
}

func openPermissionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	statements := []string{
		`CREATE TABLE groups (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL,
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
			t.Fatalf("create permission test table: %v", err)
		}
	}
	return conn
}

type groupFixture struct {
	ID          string
	Name        string
	DisplayName string
	IsProtected bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func insertGroup(t *testing.T, conn *sql.DB, fixture groupFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO groups (id, name, display_name, is_protected, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.Name,
		fixture.DisplayName,
		fixture.IsProtected,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert group: %v", err)
	}
}

type groupMembershipFixture struct {
	ID            string
	GroupID       string
	PrincipalType string
	PrincipalID   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertGroupMembership(t *testing.T, conn *sql.DB, fixture groupMembershipFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO group_memberships (id, group_id, principal_type, principal_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.GroupID,
		fixture.PrincipalType,
		fixture.PrincipalID,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert group membership: %v", err)
	}
}

type permissionAssignmentFixture struct {
	ID            string
	PrincipalType string
	PrincipalID   string
	Permission    string
	Effect        string
	ScopeType     sql.NullString
	ScopeID       sql.NullString
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertPermissionAssignment(t *testing.T, conn *sql.DB, fixture permissionAssignmentFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO permission_assignments (
			id,
			principal_type,
			principal_id,
			permission,
			effect,
			scope_type,
			scope_id,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.PrincipalType,
		fixture.PrincipalID,
		fixture.Permission,
		fixture.Effect,
		fixture.ScopeType,
		fixture.ScopeID,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert permission assignment: %v", err)
	}
}

func stringPtr(value string) *string {
	return &value
}
