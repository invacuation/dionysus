package httpapi_test

import (
	"bytes"
	"encoding/json"
	. "github.com/invacuation/dionysus/backend/internal/http"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestAuditLogRequiresAuditPermission(t *testing.T) {
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
	request := httptest.NewRequest(http.MethodGet, "/api/audit-log", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestAuditLogReturnsFilteredEventsAndEventTypes(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newAuditAdminRouter(t, conn, now)
	baseTime := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 205; index++ {
		projectID := "project-a"
		if index%2 != 0 {
			projectID = "project-b"
		}
		targetType := "import"
		if index%3 == 0 {
			targetType = "finding"
		}
		eventType := "import.trivy.success"
		if index%5 == 0 {
			eventType = "finding.status.changed"
		}
		_, err := audit.RecordEvent(t.Context(), conn, audit.Event{
			Type:               eventType,
			ActorPrincipalType: ptr("user"),
			ActorPrincipalID:   ptr("alice-id"),
			ActorDisplay:       ptr("Alice"),
			TargetType:         ptr(targetType),
			TargetID:           ptr("target-" + string(rune('0'+index%4))),
			ProjectID:          ptr(projectID),
			Metadata:           map[string]any{"index": index},
			Now:                baseTime.Add(time.Duration(index) * time.Minute),
		})
		if err != nil {
			t.Fatalf("record event %d: %v", index, err)
		}
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/audit-log?event_type=finding.status.changed&project_id=project-a&target_type=finding&target_id=target-0&limit=999", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body auditLogResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Events) == 0 || len(body.Events) > 200 {
		t.Fatalf("event count = %d, want 1..200", len(body.Events))
	}
	if len(body.EventTypes) != 3 ||
		body.EventTypes[0] != "auth.login.success" ||
		body.EventTypes[1] != "finding.status.changed" ||
		body.EventTypes[2] != "import.trivy.success" {
		t.Fatalf("event types = %#v", body.EventTypes)
	}
	for _, event := range body.Events {
		if event.EventType != "finding.status.changed" || event.ProjectID == nil || *event.ProjectID != "project-a" || event.TargetType == nil || *event.TargetType != "finding" {
			t.Fatalf("unexpected event = %#v", event)
		}
	}
	if got := body.Events[0].Metadata["index"]; got != float64(180) {
		t.Fatalf("first metadata index = %#v, want 180", got)
	}
}

func TestAuditLogFiltersCreatedRangeAndRejectsInvalidRange(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newAuditAdminRouter(t, conn, now)
	baseTime := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 5; index++ {
		_, err := audit.RecordEvent(t.Context(), conn, audit.Event{
			Type:     "finding.status.changed",
			Metadata: map[string]any{"index": index},
			Now:      baseTime.Add(time.Duration(index) * time.Hour),
		})
		if err != nil {
			t.Fatalf("record event %d: %v", index, err)
		}
	}

	validResponse := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodGet, "/api/audit-log?created_from=2026-05-08T13:00:00Z&created_to=2026-05-08T15:00:00", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		validRequest.AddCookie(cookie)
	}
	router.ServeHTTP(validResponse, validRequest)

	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid status = %d, want %d; body = %s", validResponse.Code, http.StatusOK, validResponse.Body.String())
	}
	var body auditLogResponse
	if err := json.NewDecoder(validResponse.Body).Decode(&body); err != nil {
		t.Fatalf("decode valid response: %v", err)
	}
	if len(body.Events) != 3 || body.Events[0].Metadata["index"] != float64(3) || body.Events[2].Metadata["index"] != float64(1) {
		t.Fatalf("created range events = %#v", body.Events)
	}

	invalidResponse := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/api/audit-log?created_from=2026-05-09T00:00:00Z&created_to=2026-05-08T00:00:00Z", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		invalidRequest.AddCookie(cookie)
	}
	router.ServeHTTP(invalidResponse, invalidRequest)

	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want %d; body = %s", invalidResponse.Code, http.StatusBadRequest, invalidResponse.Body.String())
	}
	assertJSONDetail(t, invalidResponse, "created_from must be at or before created_to.")
}

func TestAuditLogEnrichesMetadataWithIDs(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newAuditAdminRouter(t, conn, now)
	_, err := audit.RecordEvent(t.Context(), conn, audit.Event{
		Type:               "finding.status.changed",
		ActorPrincipalType: ptr("user"),
		ActorPrincipalID:   ptr("alice-id"),
		TargetType:         ptr("finding"),
		TargetID:           ptr("finding-id"),
		ProjectID:          ptr("project-a"),
		Metadata:           map[string]any{},
		Now:                now,
	})
	if err != nil {
		t.Fatalf("record event: %v", err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/audit-log?event_type=finding.status.changed", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body auditLogResponse
	if err := json.NewDecoder(bytes.NewReader(response.Body.Bytes())).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	event := body.Events[0]
	if event.Metadata["actor_principal_id"] != "alice-id" || event.Metadata["target_id"] != "finding-id" || event.Metadata["project_id"] != "project-a" {
		t.Fatalf("metadata = %#v", event.Metadata)
	}
}

func newAuditAdminRouter(t *testing.T, conn httpDB, now time.Time) (http.Handler, *httptest.ResponseRecorder) {
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
		Permission:    "audit_log:view",
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
