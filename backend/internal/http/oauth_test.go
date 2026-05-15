package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/identity"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestOAuthTokenExchangesClientCredentialsForBearerPair(t *testing.T) {
	conn := openOAuthTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertOAuthMachineCredential(t, conn, oauthMachineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
	}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/oauth/token",
		strings.NewReader(`{"grant_type":"client_credentials","client_id":"client-1","client_secret":"client-secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AccessToken == "" || body.RefreshToken == "" {
		t.Fatalf("token response has empty token: %#v", body)
	}
	if body.TokenType != bearerAuthScheme {
		t.Fatalf("token_type = %q, want %q", body.TokenType, bearerAuthScheme)
	}
	if body.ExpiresIn != 15*60 || body.RefreshExpiresIn != 60*60 {
		t.Fatalf("expires = %d/%d, want %d/%d", body.ExpiresIn, body.RefreshExpiresIn, 15*60, 60*60)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", response.Header().Get("Pragma"))
	}
	assertOAuthTokenCounts(t, conn, 1, 1)

	verified, err := identity.VerifyMachineAccessToken(context.Background(), conn, body.AccessToken, time.Now().UTC())
	if err != nil {
		t.Fatalf("VerifyMachineAccessToken() returned error: %v", err)
	}
	if verified == nil {
		t.Fatal("access token from response did not verify")
	}
}

func TestOAuthTokenRejectsInvalidCredentialsWithGeneric401(t *testing.T) {
	conn := openOAuthTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertOAuthMachineCredential(t, conn, oauthMachineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
	}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/oauth/token",
		strings.NewReader(`{"grant_type":"client_credentials","client_id":"client-1","client_secret":"wrong"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	assertJSONDetail(t, response, "Invalid client credentials")
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", response.Header().Get("WWW-Authenticate"))
	}
	assertOAuthTokenCounts(t, conn, 0, 0)
}

func TestOAuthTokenRejectsUnsupportedGrantType(t *testing.T) {
	conn := openOAuthTestDB(t)
	router := NewRouter(config.Settings{}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/oauth/token",
		strings.NewReader(`{"grant_type":"authorization_code","client_id":"client-1","client_secret":"secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	assertJSONDetail(t, response, "Unsupported grant_type")
}

func TestOAuthTokenAcceptsFormEncodedBody(t *testing.T) {
	conn := openOAuthTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertOAuthMachineCredential(t, conn, oauthMachineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
	}, WithDB(conn))
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"client-1"},
		"client_secret": {"client-secret"},
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	assertOAuthTokenCounts(t, conn, 1, 1)
}

func openOAuthTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	statements := []string{
		`CREATE TABLE machine_credentials (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL,
			client_id VARCHAR(64) NOT NULL,
			client_secret_digest VARCHAR(64) NOT NULL,
			is_active BOOLEAN NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE machine_tokens (
			id VARCHAR PRIMARY KEY NOT NULL,
			machine_credential_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE machine_refresh_tokens (
			id VARCHAR PRIMARY KEY NOT NULL,
			machine_credential_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	return conn
}

type oauthMachineCredentialFixture struct {
	ID                 string
	Name               string
	ClientID           string
	ClientSecretDigest string
	IsActive           bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func insertOAuthMachineCredential(t *testing.T, conn *sql.DB, fixture oauthMachineCredentialFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO machine_credentials (id, name, client_id, client_secret_digest, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.Name,
		fixture.ClientID,
		fixture.ClientSecretDigest,
		fixture.IsActive,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert machine credential: %v", err)
	}
}

func assertOAuthTokenCounts(t *testing.T, conn *sql.DB, wantAccess int, wantRefresh int) {
	t.Helper()
	var gotAccess int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM machine_tokens").Scan(&gotAccess); err != nil {
		t.Fatalf("count machine tokens: %v", err)
	}
	var gotRefresh int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM machine_refresh_tokens").Scan(&gotRefresh); err != nil {
		t.Fatalf("count machine refresh tokens: %v", err)
	}
	if gotAccess != wantAccess || gotRefresh != wantRefresh {
		t.Fatalf("token counts = access %d refresh %d, want access %d refresh %d", gotAccess, gotRefresh, wantAccess, wantRefresh)
	}
}

func assertJSONDetail(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Detail != want {
		t.Fatalf("detail = %q, want %q", body.Detail, want)
	}
}
