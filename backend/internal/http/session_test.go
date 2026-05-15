package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const pythonArgon2PasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$QuVbsCm0NDtiCTn5MdE0uw$NLEfzmIHyfK15B1McgJvPtRY4OTcNkq6/qH7KRGzfHU"

func TestAuthSessionCreatesBrowserSession(t *testing.T) {
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

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/session",
		strings.NewReader(`{"username":"alice","password":"correct horse battery staple"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body actorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ActorType != identity.ActorTypeUser || body.ActorID != "user-1" {
		t.Fatalf("actor = %s/%s, want user/user-1", body.ActorType, body.ActorID)
	}
	if body.AuthMethod != identity.AuthMethodSession {
		t.Fatalf("auth_method = %q, want session", body.AuthMethod)
	}
	if body.SessionID == nil {
		t.Fatal("session_id is nil, want created session id")
	}
	if response.Result().Cookies()[0].Name != sessionCookieName {
		t.Fatalf("cookie name = %q, want %q", response.Result().Cookies()[0].Name, sessionCookieName)
	}
	assertHTTPSessionCount(t, conn, 1)

	meResponse := httptest.NewRecorder()
	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	for _, cookie := range response.Result().Cookies() {
		meRequest.AddCookie(cookie)
	}
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK {
		t.Fatalf("me status = %d, want %d; body = %s", meResponse.Code, http.StatusOK, meResponse.Body.String())
	}
}

func TestAuthSessionRejectsInvalidCredentials(t *testing.T) {
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

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/session",
		strings.NewReader(`{"username":"alice","password":"wrong"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	assertJSONDetail(t, response, "Invalid username or password")
	assertHTTPSessionCount(t, conn, 0)
}

func TestAuthSessionDeleteRevokesBrowserSession(t *testing.T) {
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
	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/session",
		strings.NewReader(`{"username":"alice","password":"correct horse battery staple"}`),
	)
	loginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d", loginResponse.Code, http.StatusOK)
	}

	logoutResponse := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodDelete, "/api/auth/session", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		logoutRequest.AddCookie(cookie)
	}
	router.ServeHTTP(logoutResponse, logoutRequest)

	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", logoutResponse.Code, http.StatusNoContent)
	}
	assertHTTPSessionRevoked(t, conn)

	meResponse := httptest.NewRecorder()
	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		meRequest.AddCookie(cookie)
	}
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusUnauthorized {
		t.Fatalf("me status after logout = %d, want %d", meResponse.Code, http.StatusUnauthorized)
	}
}

func openSessionHTTPTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	statements := []string{
		`CREATE TABLE users (
			id VARCHAR PRIMARY KEY NOT NULL,
			username VARCHAR(150) NOT NULL,
			display_name VARCHAR(200) NOT NULL,
			is_active BOOLEAN NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE user_password_credentials (
			id VARCHAR PRIMARY KEY NOT NULL,
			user_id VARCHAR NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE user_sessions (
			id VARCHAR PRIMARY KEY NOT NULL,
			user_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			user_agent TEXT,
			ip_address VARCHAR(64),
			expires_at DATETIME NOT NULL,
			idle_expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			last_seen_at DATETIME NOT NULL,
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

type httpUserFixture struct {
	ID           string
	Username     string
	DisplayName  string
	IsActive     bool
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func insertHTTPUser(t *testing.T, conn *sql.DB, fixture httpUserFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO users (id, username, display_name, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.Username,
		fixture.DisplayName,
		fixture.IsActive,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO user_password_credentials (id, user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"password-1",
		fixture.ID,
		fixture.PasswordHash,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert password credential: %v", err)
	}
}

func assertHTTPSessionCount(t *testing.T, conn *sql.DB, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM user_sessions").Scan(&got); err != nil {
		t.Fatalf("count user sessions: %v", err)
	}
	if got != want {
		t.Fatalf("session count = %d, want %d", got, want)
	}
}

func assertHTTPSessionRevoked(t *testing.T, conn *sql.DB) {
	t.Helper()
	var revokedAt sql.NullTime
	if err := conn.QueryRowContext(context.Background(), "SELECT revoked_at FROM user_sessions").Scan(&revokedAt); err != nil {
		t.Fatalf("select revoked_at: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatal("revoked_at is NULL, want timestamp")
	}
}
