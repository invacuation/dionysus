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

func TestMachineCredentialsCreateReturnsSecretOnceAndListIsSafe(t *testing.T) {
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

func TestMachineCredentialRegenerateSecretInvalidatesOldSecretAndRevokesTokens(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router := newMachineCredentialAdminTestRouter(t, conn)
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")
	created := createHTTPMachineCredential(t, router, loginResponse, "ci-runner")
	oldTokenResponse := exchangeHTTPMachineToken(t, router, created.ClientID, created.ClientSecret)
	oldAccessToken := oldTokenResponse.AccessToken

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/machine-credentials/"+created.ID+"/regenerate-secret",
		strings.NewReader(`{"revoke_tokens":true}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("regenerate status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var regenerated machineCredentialWithSecretResponse
	if err := json.NewDecoder(response.Body).Decode(&regenerated); err != nil {
		t.Fatalf("decode regenerate response: %v", err)
	}
	if regenerated.ClientSecret == "" || regenerated.ClientSecret == created.ClientSecret {
		t.Fatalf("new secret = %q, old secret = %q", regenerated.ClientSecret, created.ClientSecret)
	}
	oldSecretResponse := exchangeHTTPMachineToken(t, router, created.ClientID, created.ClientSecret)
	if oldSecretResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old secret exchange status = %d, want %d", oldSecretResponse.StatusCode, http.StatusUnauthorized)
	}
	newSecretResponse := exchangeHTTPMachineToken(t, router, created.ClientID, regenerated.ClientSecret)
	if newSecretResponse.StatusCode != http.StatusOK {
		t.Fatalf("new secret exchange status = %d, want %d", newSecretResponse.StatusCode, http.StatusOK)
	}
	meResponse := httptest.NewRecorder()
	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+oldAccessToken)
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old bearer status = %d, want %d", meResponse.Code, http.StatusUnauthorized)
	}
}

func TestMachineCredentialRevokeDisablesCredentialAndRevokesTokens(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router := newMachineCredentialAdminTestRouter(t, conn)
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")
	created := createHTTPMachineCredential(t, router, loginResponse, "ci-runner")
	tokenResponse := exchangeHTTPMachineToken(t, router, created.ClientID, created.ClientSecret)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/machine-credentials/"+created.ID+"/revoke",
		strings.NewReader(`{"revoke_tokens":true}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var revoked machineCredentialResponse
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if revoked.IsActive || revoked.RevokedAt == nil {
		t.Fatalf("revoked credential active/revoked = %t/%v, want false/timestamp", revoked.IsActive, revoked.RevokedAt)
	}
	exchangeResponse := exchangeHTTPMachineToken(t, router, created.ClientID, created.ClientSecret)
	if exchangeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked credential exchange status = %d, want %d", exchangeResponse.StatusCode, http.StatusUnauthorized)
	}
	meResponse := httptest.NewRecorder()
	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer status = %d, want %d", meResponse.Code, http.StatusUnauthorized)
	}
}

type oauthTokenResponse struct {
	StatusCode   int
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func newMachineCredentialAdminTestRouter(t *testing.T, conn httpDB) http.Handler {
	t.Helper()
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
	insertHTTPPermission(t, conn, httpPermissionFixture{
		ID:            "permission-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "credential:manage",
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	return NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:         30,
		SessionAbsoluteTimeoutMinutes:     480,
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
		LocalAuthEnabled:                  true,
	}, WithDB(conn))
}

func createHTTPMachineCredential(t *testing.T, router http.Handler, loginResponse *httptest.ResponseRecorder, name string) machineCredentialWithSecretResponse {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/machine-credentials",
		strings.NewReader(`{"name":"`+name+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var created machineCredentialWithSecretResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return created
}

func exchangeHTTPMachineToken(t *testing.T, router http.Handler, clientID string, clientSecret string) oauthTokenResponse {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/oauth/token",
		strings.NewReader(`{"grant_type":"client_credentials","client_id":"`+clientID+`","client_secret":"`+clientSecret+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	result := oauthTokenResponse{StatusCode: response.Code}
	if response.Code == http.StatusOK {
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatalf("decode token response: %v", err)
		}
	}
	return result
}
