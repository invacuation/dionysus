package httpapi_test

import (
	"encoding/json"
	. "github.com/invacuation/dionysus/backend/internal/http"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestAuthMeReturnsMachineActorForBearerToken(t *testing.T) {
	conn := openOAuthTestDB(t)
	now := time.Now().UTC()
	insertOAuthMachineCredential(t, conn, oauthMachineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})
	pair, err := identity.ExchangeMachineClientSecret(t.Context(), conn, identity.MachineClientSecretExchange{
		ClientID:                "client-1",
		ClientSecret:            "client-secret",
		Now:                     now,
		AccessExpiresInMinutes:  15,
		RefreshExpiresInMinutes: 60,
	})
	if err != nil {
		t.Fatalf("ExchangeMachineClientSecret() returned error: %v", err)
	}
	router := NewRouter(config.Settings{
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
		LocalAuthEnabled:                  true,
	}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body actorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ActorType != identity.ActorTypeMachine || body.ActorID != "machine-1" {
		t.Fatalf("actor = %s/%s, want machine/machine-1", body.ActorType, body.ActorID)
	}
	if body.DisplayName != "trivy-uploader" {
		t.Fatalf("display_name = %q, want trivy-uploader", body.DisplayName)
	}
	if body.PrincipalType != identity.PrincipalTypeMachine || body.PrincipalID != "machine-1" {
		t.Fatalf("principal = %s/%s, want machine/machine-1", body.PrincipalType, body.PrincipalID)
	}
	if body.AuthMethod != identity.AuthMethodBearerToken {
		t.Fatalf("auth_method = %q, want bearer_token", body.AuthMethod)
	}
	if body.MachineTokenID == nil {
		t.Fatal("machine_token_id is nil, want token id")
	}
	if !body.BearerTokenPresent || body.SessionCookiePresent || body.MixedCredentialsPresent {
		t.Fatalf("credential flags = bearer:%t session:%t mixed:%t", body.BearerTokenPresent, body.SessionCookiePresent, body.MixedCredentialsPresent)
	}
	if !body.LocalAuthEnabled {
		t.Fatal("local_auth_enabled = false, want true")
	}
}

func TestAuthMeReturnsCurrentActorCapabilities(t *testing.T) {
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
	projectID := insertHTTPProject(t, conn, httpProjectFixture{
		ID:                  "capabilities-project",
		Slug:                "capabilities-project",
		Name:                "Capabilities Project",
		SLATrackingEnabled:  true,
		SLAReportingEnabled: true,
		GracePeriodPercent:  100,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{
		ID:            "project-view",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     ptr("project"),
		ScopeID:       ptr(projectID),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{
		ID:            "finding-view",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "finding:view",
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     ptr("project"),
		ScopeID:       ptr(projectID),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body actorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Capabilities.Navigation.Findings || !body.Capabilities.Navigation.Inventory {
		t.Fatalf("navigation capabilities = %#v, want findings and inventory", body.Capabilities.Navigation)
	}
	if body.Capabilities.Navigation.Imports || body.Capabilities.Navigation.Admin {
		t.Fatalf("navigation capabilities = %#v, want imports and admin hidden", body.Capabilities.Navigation)
	}
	if body.Capabilities.Admin.AuditLog || body.Capabilities.Admin.Access {
		t.Fatalf("admin capabilities = %#v, want no admin tabs", body.Capabilities.Admin)
	}
}

func TestAuthMeTreatsAdminWildcardAsProjectAreaAccess(t *testing.T) {
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
		ID:            "admin",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    identity.AdminPermission,
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body actorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Capabilities.Navigation.Findings || !body.Capabilities.Navigation.Imports || !body.Capabilities.Navigation.Admin {
		t.Fatalf("navigation capabilities = %#v, want admin wildcard project areas", body.Capabilities.Navigation)
	}
}

func TestAuthMeRejectsMissingCredentials(t *testing.T) {
	conn := openOAuthTestDB(t)
	router := NewRouter(config.Settings{}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	assertJSONDetail(t, response, "Not authenticated")
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", response.Header().Get("WWW-Authenticate"))
	}
}
