package identity_test

import (
	"context"
	"database/sql"
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"testing"
	"time"
)

func TestEnsureActorPermissionAllowsAdminWildcard(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-1",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    AdminPermission,
		Effect:        PermissionEffectAllow,
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	actor := AuthenticatedActor{PrincipalType: PrincipalTypeUser, PrincipalID: "user-1"}
	got, err := EnsureActorPermission(context.Background(), conn, actor, PermissionRequest{
		Permission: "audit_log:view",
	})
	if err != nil {
		t.Fatalf("EnsureActorPermission() returned error: %v", err)
	}
	if got.PrincipalID != "user-1" {
		t.Fatalf("PrincipalID = %q, want user-1", got.PrincipalID)
	}
}

func TestEnsureActorPermissionScopedDenyOverridesAdminWildcard(t *testing.T) {
	conn := openPermissionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-1",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    AdminPermission,
		Effect:        PermissionEffectAllow,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	insertPermissionAssignment(t, conn, permissionAssignmentFixture{
		ID:            "assignment-2",
		PrincipalType: PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "audit_log:view",
		Effect:        PermissionEffectDeny,
		ScopeType:     sql.NullString{String: "project", Valid: true},
		ScopeID:       sql.NullString{String: "project-1", Valid: true},
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	actor := AuthenticatedActor{PrincipalType: PrincipalTypeUser, PrincipalID: "user-1"}
	_, err := EnsureActorPermission(context.Background(), conn, actor, PermissionRequest{
		Permission: "audit_log:view",
		ScopeType:  stringPtr("project"),
		ScopeID:    stringPtr("project-1"),
	})
	if err == nil {
		t.Fatal("EnsureActorPermission() error = nil, want forbidden")
	}
	if err.Error() != "Forbidden" {
		t.Fatalf("error = %q, want Forbidden", err.Error())
	}
}

func TestEnsureActorPermissionRejectsMissingGrant(t *testing.T) {
	conn := openPermissionTestDB(t)

	actor := AuthenticatedActor{PrincipalType: PrincipalTypeUser, PrincipalID: "user-1"}
	_, err := EnsureActorPermission(context.Background(), conn, actor, PermissionRequest{
		Permission: "audit_log:view",
	})
	if err == nil {
		t.Fatal("EnsureActorPermission() error = nil, want forbidden")
	}
	if err.Error() != "Forbidden" {
		t.Fatalf("error = %q, want Forbidden", err.Error())
	}
}
