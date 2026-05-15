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

type httpDB = *sql.DB

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

func TestAuthPasswordChangeUpdatesPassword(t *testing.T) {
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

	changeResponse := httptest.NewRecorder()
	changeRequest := httptest.NewRequest(
		http.MethodPatch,
		"/api/auth/password",
		strings.NewReader(`{"current_password":"correct horse battery staple","new_password":"new correct horse battery"}`),
	)
	changeRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		changeRequest.AddCookie(cookie)
	}
	router.ServeHTTP(changeResponse, changeRequest)

	if changeResponse.Code != http.StatusNoContent {
		t.Fatalf("password change status = %d, want %d; body = %s", changeResponse.Code, http.StatusNoContent, changeResponse.Body.String())
	}
	oldLogin := loginHTTPUser(t, router, "correct horse battery staple")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password login status = %d, want %d", oldLogin.Code, http.StatusUnauthorized)
	}
	newLogin := loginHTTPUser(t, router, "new correct horse battery")
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password login status = %d, want %d; body = %s", newLogin.Code, http.StatusOK, newLogin.Body.String())
	}
}

func TestAuthPasswordChangeRejectsWrongCurrentPassword(t *testing.T) {
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

	changeResponse := httptest.NewRecorder()
	changeRequest := httptest.NewRequest(
		http.MethodPatch,
		"/api/auth/password",
		strings.NewReader(`{"current_password":"wrong password value","new_password":"new correct horse battery"}`),
	)
	changeRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		changeRequest.AddCookie(cookie)
	}
	router.ServeHTTP(changeResponse, changeRequest)

	if changeResponse.Code != http.StatusBadRequest {
		t.Fatalf("password change status = %d, want %d", changeResponse.Code, http.StatusBadRequest)
	}
	assertJSONDetail(t, changeResponse, "Current password is incorrect")
	validLogin := loginHTTPUser(t, router, "correct horse battery staple")
	if validLogin.Code != http.StatusOK {
		t.Fatalf("valid login status = %d, want %d", validLogin.Code, http.StatusOK)
	}
}

func TestAuthPasswordChangeDisabledWhenLocalAuthDisabled(t *testing.T) {
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
	loginRouter := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, loginRouter, "correct horse battery staple")
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              false,
	}, WithDB(conn))

	changeResponse := httptest.NewRecorder()
	changeRequest := httptest.NewRequest(
		http.MethodPatch,
		"/api/auth/password",
		strings.NewReader(`{"current_password":"correct horse battery staple","new_password":"new correct horse battery"}`),
	)
	changeRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		changeRequest.AddCookie(cookie)
	}
	router.ServeHTTP(changeResponse, changeRequest)

	if changeResponse.Code != http.StatusForbidden {
		t.Fatalf("password change status = %d, want %d", changeResponse.Code, http.StatusForbidden)
	}
	assertJSONDetail(t, changeResponse, "Local authentication is disabled")
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
			username VARCHAR(150) NOT NULL UNIQUE,
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
		`CREATE TABLE machine_credentials (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL UNIQUE,
			client_id VARCHAR(64) NOT NULL UNIQUE,
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
		`CREATE TABLE group_memberships (
			id VARCHAR PRIMARY KEY NOT NULL,
			group_id VARCHAR NOT NULL,
			principal_type VARCHAR(20) NOT NULL,
			principal_id VARCHAR(36) NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE groups (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL UNIQUE,
			display_name VARCHAR(200) NOT NULL,
			is_protected BOOLEAN NOT NULL,
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
		`CREATE TABLE projects (
			id VARCHAR PRIMARY KEY NOT NULL,
			slug VARCHAR(150) NOT NULL UNIQUE,
			name VARCHAR(200) NOT NULL,
			description TEXT,
			sla_tracking_enabled BOOLEAN NOT NULL,
			sla_reporting_enabled BOOLEAN NOT NULL,
			grace_period_enabled BOOLEAN NOT NULL,
			grace_period_percent INTEGER NOT NULL,
			require_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
			critical_sla_days INTEGER NOT NULL DEFAULT 30,
			high_sla_days INTEGER NOT NULL DEFAULT 60,
			medium_sla_days INTEGER NOT NULL DEFAULT 90,
			low_sla_days INTEGER NOT NULL DEFAULT 180,
			unknown_sla_days INTEGER NOT NULL DEFAULT 365,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE asset_nodes (
			id VARCHAR PRIMARY KEY NOT NULL,
			project_id VARCHAR NOT NULL,
			parent_id VARCHAR,
			node_type VARCHAR(50) NOT NULL,
			name VARCHAR(255) NOT NULL,
			path TEXT NOT NULL,
			target_ref TEXT,
			metadata_json TEXT NOT NULL,
			sla_tracking_enabled BOOLEAN,
			sla_reporting_enabled BOOLEAN,
			grace_period_enabled BOOLEAN,
			grace_period_percent INTEGER,
			sort_order INTEGER NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			UNIQUE (project_id, path)
		)`,
		`CREATE TABLE app_security_settings (
			id VARCHAR(50) PRIMARY KEY NOT NULL,
			force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
			session_idle_timeout_minutes INTEGER,
			session_absolute_timeout_minutes INTEGER,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE audit_log_events (
			id VARCHAR PRIMARY KEY NOT NULL,
			event_type VARCHAR(120) NOT NULL,
			actor_principal_type VARCHAR(50),
			actor_principal_id VARCHAR(36),
			actor_display VARCHAR(255),
			target_type VARCHAR(120),
			target_id VARCHAR(255),
			project_id VARCHAR(36),
			ip_address VARCHAR(120),
			user_agent TEXT,
			metadata_json TEXT NOT NULL,
			created_at DATETIME NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	return conn
}

type httpMachineCredentialFixture struct {
	ID                 string
	Name               string
	ClientID           string
	ClientSecretDigest string
	IsActive           bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func insertHTTPMachineCredential(t *testing.T, conn *sql.DB, fixture httpMachineCredentialFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO machine_credentials (
			id,
			name,
			client_id,
			client_secret_digest,
			is_active,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
		"password-"+fixture.ID,
		fixture.ID,
		fixture.PasswordHash,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert password credential: %v", err)
	}
}

func loginHTTPUser(t *testing.T, router http.Handler, password string) *httptest.ResponseRecorder {
	t.Helper()
	return loginNamedHTTPUser(t, router, "alice", password)
}

func loginNamedHTTPUser(t *testing.T, router http.Handler, username string, password string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/session",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
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

type httpPermissionFixture struct {
	ID            string
	PrincipalType string
	PrincipalID   string
	Permission    string
	Effect        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertHTTPPermission(t *testing.T, conn *sql.DB, fixture httpPermissionFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO permission_assignments (
			id,
			principal_type,
			principal_id,
			permission,
			effect,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.PrincipalType,
		fixture.PrincipalID,
		fixture.Permission,
		fixture.Effect,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
}

type httpGroupFixture struct {
	ID          string
	Name        string
	DisplayName string
	IsProtected bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func insertHTTPGroup(t *testing.T, conn *sql.DB, fixture httpGroupFixture) {
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

type httpMembershipFixture struct {
	ID            string
	GroupID       string
	PrincipalType string
	PrincipalID   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertHTTPMembership(t *testing.T, conn *sql.DB, fixture httpMembershipFixture) {
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
		t.Fatalf("insert membership: %v", err)
	}
}
