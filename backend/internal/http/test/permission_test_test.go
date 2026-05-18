package httpapi_test

import (
	"encoding/json"
	. "github.com/invacuation/dionysus/backend/internal/http"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestPermissionTestReturnsDirectAllow(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newPermissionTestAdminRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{
		ID:            "permission-2",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     ptr("project"),
		ScopeID:       ptr("project-1"),
		CreatedAt:     now.Add(-time.Minute),
		UpdatedAt:     now.Add(-time.Minute),
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/permission-test",
		strings.NewReader(`{"principal_type":"user","principal_id":"user-1","permission":"project:view","scope_type":"project","scope_id":"project-1"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body permissionTestResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Allowed {
		t.Fatalf("allowed = false, want true; explanation = %q", body.Explanation)
	}
	if body.Explanation != "direct allow matched project:view on project:project-1" {
		t.Fatalf("explanation = %q", body.Explanation)
	}
}

func TestPermissionTestRequiresPermission(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: argon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/permission-test",
		strings.NewReader(`{"principal_type":"user","principal_id":"user-1","permission":"project:view"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func newPermissionTestAdminRouter(t *testing.T, conn httpDB, now time.Time) (http.Handler, *httptest.ResponseRecorder) {
	t.Helper()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: argon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	insertHTTPPermission(t, conn, httpPermissionFixture{
		ID:            "permission-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "permission:test",
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d; body = %s", loginResponse.Code, http.StatusOK, loginResponse.Body.String())
	}
	return router, loginResponse
}

type httpScopedPermissionFixture struct {
	ID            string
	PrincipalType string
	PrincipalID   string
	Permission    string
	Effect        string
	ScopeType     *string
	ScopeID       *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertScopedHTTPPermission(t *testing.T, conn httpDB, fixture httpScopedPermissionFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		t.Context(),
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
		t.Fatalf("insert scoped permission: %v", err)
	}
}

func ptr(value string) *string {
	return &value
}
