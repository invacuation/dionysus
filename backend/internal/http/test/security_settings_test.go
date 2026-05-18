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

func TestSecuritySettingsReadDefaults(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newSecuritySettingsAdminTestRouter(t, conn)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/security-settings", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body securitySettingsResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ForcePeerReviewForStatusChanges || body.SessionIdleTimeoutMinutes != 30 || body.SessionAbsoluteTimeoutMinutes != 480 {
		t.Fatalf("settings = %#v, want defaults", body)
	}
}

func TestSecuritySettingsUpdate(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newSecuritySettingsAdminTestRouter(t, conn)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPatch,
		"/api/admin/security-settings",
		strings.NewReader(`{"force_peer_review_for_status_changes":true,"session_idle_timeout_minutes":45,"session_absolute_timeout_minutes":720}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body securitySettingsResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.ForcePeerReviewForStatusChanges || body.SessionIdleTimeoutMinutes != 45 || body.SessionAbsoluteTimeoutMinutes != 720 {
		t.Fatalf("settings = %#v, want updated values", body)
	}
}

func TestSecuritySettingsRejectInvalidTimeouts(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newSecuritySettingsAdminTestRouter(t, conn)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPatch,
		"/api/admin/security-settings",
		strings.NewReader(`{"force_peer_review_for_status_changes":false,"session_idle_timeout_minutes":60,"session_absolute_timeout_minutes":30}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	assertJSONDetail(t, response, "Invalid security settings request")
}

func newSecuritySettingsAdminTestRouter(t *testing.T, conn httpDB) (http.Handler, *httptest.ResponseRecorder) {
	t.Helper()
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
		Permission:    identity.AdminPermission,
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
	return router, loginResponse
}
