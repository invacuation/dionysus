package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestMachineCredentialsCreateReturnsSecretOnceAndListIsSafe(t *testing.T) {
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
		Permission:    "credential:manage",
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

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/machine-credentials",
		strings.NewReader(`{"name":"ci-runner"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		createRequest.AddCookie(cookie)
	}
	router.ServeHTTP(createResponse, createRequest)

	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", createResponse.Code, http.StatusCreated, createResponse.Body.String())
	}
	var created machineCredentialWithSecretResponse
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Name != "ci-runner" || created.ClientID == "" || created.ClientSecret == "" {
		t.Fatalf("created credential missing expected fields: %#v", created)
	}
	if !created.IsActive || created.RevokedAt != nil {
		t.Fatalf("created active/revoked = %t/%v, want true/nil", created.IsActive, created.RevokedAt)
	}

	listResponse := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/api/admin/machine-credentials", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		listRequest.AddCookie(cookie)
	}
	router.ServeHTTP(listResponse, listRequest)

	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d; body = %s", listResponse.Code, http.StatusOK, listResponse.Body.String())
	}
	var listed machineCredentialListResponse
	if err := json.NewDecoder(listResponse.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listed.Credentials) != 1 {
		t.Fatalf("credential count = %d, want 1", len(listed.Credentials))
	}
	if listed.Credentials[0].ID != created.ID || listed.Credentials[0].Name != "ci-runner" {
		t.Fatalf("listed credential = %#v, want created ci-runner", listed.Credentials[0])
	}
}

func TestMachineCredentialsRequireCredentialManage(t *testing.T) {
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
	request := httptest.NewRequest(http.MethodGet, "/api/admin/machine-credentials", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	assertJSONDetail(t, response, "Forbidden")
}
