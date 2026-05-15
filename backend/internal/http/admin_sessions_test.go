package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestAdminSessionsListReturnsSafeSessionsNewestFirst(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newSessionAdminRouter(t, conn, now)
	currentSessionID := sessionIDFromLogin(t, loginResponse)
	setHTTPSessionTimes(t, conn, currentSessionID, now, now.Add(30*time.Minute), now.Add(2*time.Hour), nil)
	olderSessionID := insertHTTPSession(t, conn, httpSessionFixture{
		ID:            "session-older",
		UserID:        "user-1",
		TokenDigest:   "older-digest",
		UserAgent:     ptr("Older browser"),
		IPAddress:     ptr("198.51.100.10"),
		CreatedAt:     now.Add(-24 * time.Hour),
		LastSeenAt:    now.Add(-24 * time.Hour),
		IdleExpiresAt: now.Add(-23 * time.Hour),
		ExpiresAt:     now.Add(-22 * time.Hour),
		RevokedAt:     timePtr(now.Add(-23 * time.Hour)),
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/sessions", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	responseBody := response.Body.Bytes()
	var body adminSessionListResponse
	if err := json.NewDecoder(bytes.NewReader(responseBody)).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Sessions) != 2 {
		t.Fatalf("session count = %d, want 2", len(body.Sessions))
	}
	if body.Sessions[0].ID != currentSessionID || body.Sessions[1].ID != olderSessionID {
		t.Fatalf("session order = %s, %s; want current then older", body.Sessions[0].ID, body.Sessions[1].ID)
	}
	if !body.Sessions[0].Active {
		t.Fatal("current session active = false, want true")
	}
	if body.Sessions[1].Active {
		t.Fatal("older session active = true, want false")
	}
	var rawBody map[string][]map[string]any
	if err := json.Unmarshal(responseBody, &rawBody); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if _, ok := rawBody["sessions"][1]["token_digest"]; ok {
		t.Fatal("response exposed token_digest")
	}
	if _, ok := rawBody["sessions"][1]["token"]; ok {
		t.Fatal("response exposed token")
	}
	if body.Sessions[1].Username != "alice" || body.Sessions[1].DisplayName != "Alice" {
		t.Fatalf("older session user = %s/%s, want alice/Alice", body.Sessions[1].Username, body.Sessions[1].DisplayName)
	}
	if body.Sessions[1].IPAddress == nil || *body.Sessions[1].IPAddress != "198.51.100.10" {
		t.Fatalf("older session ip = %#v, want 198.51.100.10", body.Sessions[1].IPAddress)
	}
}

func TestAdminSessionsRevokeStampsRevokedAt(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newSessionAdminRouter(t, conn, now)
	targetSessionID := insertHTTPSession(t, conn, httpSessionFixture{
		ID:            "session-target",
		UserID:        "user-1",
		TokenDigest:   "target-digest",
		UserAgent:     ptr("Target browser"),
		IPAddress:     ptr("203.0.113.7"),
		CreatedAt:     now.Add(-time.Hour),
		LastSeenAt:    now.Add(-time.Hour),
		IdleExpiresAt: now.Add(time.Hour),
		ExpiresAt:     now.Add(2 * time.Hour),
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/sessions/"+targetSessionID+"/revoke", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body adminSessionResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ID != targetSessionID {
		t.Fatalf("id = %q, want %q", body.ID, targetSessionID)
	}
	if body.Active {
		t.Fatal("active = true, want false")
	}
	if body.RevokedAt == nil {
		t.Fatal("revoked_at is nil, want timestamp")
	}
	var revokedAt sql.NullTime
	if err := conn.QueryRowContext(t.Context(), "SELECT revoked_at FROM user_sessions WHERE id = ?", targetSessionID).Scan(&revokedAt); err != nil {
		t.Fatalf("select revoked_at: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatal("stored revoked_at is NULL")
	}
}

func TestAdminSessionsRevokeUnknownSessionReturns404(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newSessionAdminRouter(t, conn, now)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/sessions/missing/revoke", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusNotFound, response.Body.String())
	}
	assertJSONDetail(t, response, "Session not found")
}

func newSessionAdminRouter(t *testing.T, conn httpDB, now time.Time) (http.Handler, *httptest.ResponseRecorder) {
	t.Helper()
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
		Permission:    "admin:*",
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

func sessionIDFromLogin(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body actorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if body.SessionID == nil {
		t.Fatal("session_id is nil")
	}
	return *body.SessionID
}

type httpSessionFixture struct {
	ID            string
	UserID        string
	TokenDigest   string
	UserAgent     *string
	IPAddress     *string
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

func insertHTTPSession(t *testing.T, conn httpDB, fixture httpSessionFixture) string {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO user_sessions (
			id,
			user_id,
			token_digest,
			user_agent,
			ip_address,
			expires_at,
			idle_expires_at,
			revoked_at,
			last_seen_at,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.UserID,
		fixture.TokenDigest,
		fixture.UserAgent,
		fixture.IPAddress,
		fixture.ExpiresAt,
		fixture.IdleExpiresAt,
		fixture.RevokedAt,
		fixture.LastSeenAt,
		fixture.CreatedAt,
		fixture.CreatedAt,
	); err != nil {
		t.Fatalf("insert user session: %v", err)
	}
	return fixture.ID
}

func setHTTPSessionTimes(t *testing.T, conn httpDB, sessionID string, createdAt time.Time, idleExpiresAt time.Time, expiresAt time.Time, revokedAt *time.Time) {
	t.Helper()
	if _, err := conn.ExecContext(
		t.Context(),
		`UPDATE user_sessions
		SET created_at = ?, last_seen_at = ?, idle_expires_at = ?, expires_at = ?, revoked_at = ?, updated_at = ?
		WHERE id = ?`,
		createdAt,
		createdAt,
		idleExpiresAt,
		expiresAt,
		revokedAt,
		createdAt,
		sessionID,
	); err != nil {
		t.Fatalf("update session times: %v", err)
	}
}

func timePtr(value time.Time) *time.Time {
	return &value
}
