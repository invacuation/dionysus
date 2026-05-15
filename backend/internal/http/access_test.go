package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestAccessListReturnsSafeAccessManagementData(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	insertHTTPPermission(t, conn, httpPermissionFixture{
		ID:            "permission-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "access:manage",
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	insertHTTPGroup(t, conn, httpGroupFixture{
		ID:          "group-1",
		Name:        "operators",
		DisplayName: "Operators",
		CreatedAt:   now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
	})
	insertHTTPMembership(t, conn, httpMembershipFixture{
		ID:            "membership-1",
		GroupID:       "group-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/access", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body accessListResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Users) != 1 || body.Users[0].Username != "alice" {
		t.Fatalf("users = %#v, want alice", body.Users)
	}
	if len(body.Groups) != 1 || body.Groups[0].Name != "operators" {
		t.Fatalf("groups = %#v, want operators", body.Groups)
	}
	if len(body.Memberships) != 1 || body.Memberships[0].GroupID != "group-1" {
		t.Fatalf("memberships = %#v, want group-1 membership", body.Memberships)
	}
	if len(body.PermissionAssignments) != 1 || body.PermissionAssignments[0].Permission != "access:manage" {
		t.Fatalf("permission assignments = %#v, want access:manage", body.PermissionAssignments)
	}
	if len(body.AvailablePermissions) == 0 {
		t.Fatal("available permissions is empty")
	}
}

func TestAccessListRequiresAccessManage(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
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
	request := httptest.NewRequest(http.MethodGet, "/api/admin/access", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	assertJSONDetail(t, response, "Forbidden")
}
