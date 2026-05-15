package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestProjectsListFiltersByProjectViewPermission(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	alphaID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", Description: ptr("Primary inventory"), SLATrackingEnabled: false, SLAReportingEnabled: false, RequirePeerReviewForStatusChanges: true, GracePeriodEnabled: true, GracePeriodPercent: 50, CreatedAt: now, UpdatedAt: now})
	insertHTTPProject(t, conn, httpProjectFixture{ID: "project-beta", Slug: "beta", Name: "Beta", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{
		ID:            "project-view-alpha",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "project:view",
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     ptr("project"),
		ScopeID:       ptr(alphaID),
		CreatedAt:     now,
		UpdatedAt:     now,
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body projectListResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Projects) != 1 {
		t.Fatalf("project count = %d, want 1", len(body.Projects))
	}
	project := body.Projects[0]
	if project.ID != alphaID || project.Slug != "alpha" || project.Name != "Alpha" {
		t.Fatalf("project = %#v, want alpha", project)
	}
	if project.Description == nil || *project.Description != "Primary inventory" {
		t.Fatalf("description = %#v, want Primary inventory", project.Description)
	}
	if project.SLATrackingEnabled || project.SLAReportingEnabled || !project.RequirePeerReviewForStatusChanges || !project.GracePeriodEnabled || project.GracePeriodPercent != 50 {
		t.Fatalf("project flags = %#v", project)
	}
}

func TestProjectCreateReturnsProjectAndRecordsAuditEvent(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertHTTPPermission(t, conn, httpPermissionFixture{ID: "project-create", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "project:create", Effect: identity.PermissionEffectAllow, CreatedAt: now, UpdatedAt: now})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{"slug":"alpha","name":" Alpha Inventory ","description":"Primary inventory","sla_tracking_enabled":false,"sla_reporting_enabled":false,"require_peer_review_for_status_changes":true,"grace_period_enabled":true,"grace_period_percent":50}`))
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var body projectResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Slug != "alpha" || body.Name != "Alpha Inventory" || body.Description == nil || *body.Description != "Primary inventory" {
		t.Fatalf("project = %#v", body)
	}
	if body.SLATrackingEnabled || body.SLAReportingEnabled || !body.RequirePeerReviewForStatusChanges || !body.GracePeriodEnabled || body.GracePeriodPercent != 50 {
		t.Fatalf("project flags = %#v", body)
	}
	assertAuditEvent(t, conn, "inventory.project.create", body.ID, `"slug":"alpha"`)
}

func TestProjectCreateRejectsDuplicateAndInvalidSlug(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertHTTPPermission(t, conn, httpPermissionFixture{ID: "project-create", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "project:create", Effect: identity.PermissionEffectAllow, CreatedAt: now, UpdatedAt: now})

	duplicate := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects", `{"slug":"alpha","name":"Alpha Copy"}`)
	invalid := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects", `{"slug":"bad slug","name":"Bad Slug"}`)

	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d; body = %s", duplicate.Code, http.StatusConflict, duplicate.Body.String())
	}
	assertJSONDetail(t, duplicate, "Project slug or name already exists")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want %d; body = %s", invalid.Code, http.StatusBadRequest, invalid.Body.String())
	}
	assertJSONDetail(t, invalid, "project slug must not contain whitespace")
}

func TestProjectUpdateChangesSettingsAndRecordsAudit(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "project-update", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "project:update", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedProjectRequest(t, router, loginResponse, http.MethodPatch, "/api/projects/"+projectID, `{"slug":"beta","name":" Beta Inventory ","sla_tracking_enabled":false,"sla_reporting_enabled":false,"require_peer_review_for_status_changes":true,"grace_period_enabled":true,"grace_period_percent":70}`)
	invalid := authedProjectRequest(t, router, loginResponse, http.MethodPatch, "/api/projects/"+projectID, `{"grace_period_percent":0}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body projectResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Slug != "beta" || body.Name != "Beta Inventory" || body.SLATrackingEnabled || body.SLAReportingEnabled || !body.RequirePeerReviewForStatusChanges || !body.GracePeriodEnabled || body.GracePeriodPercent != 70 {
		t.Fatalf("project = %#v", body)
	}
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want %d; body = %s", invalid.Code, http.StatusBadRequest, invalid.Body.String())
	}
	assertAuditEvent(t, conn, "inventory.project.update", projectID, `"changed_fields"`)
}

func TestProjectDeleteRemovesProjectAndRecordsAudit(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "asset-1", ProjectID: projectID, NodeType: "folder", Name: "images", Path: "images", MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "project-delete", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "project:delete", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedProjectRequest(t, router, loginResponse, http.MethodDelete, "/api/projects/"+projectID, ``)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusNoContent, response.Body.String())
	}
	var count int
	if err := conn.QueryRowContext(t.Context(), "SELECT count(*) FROM projects WHERE id = ?", projectID).Scan(&count); err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if count != 0 {
		t.Fatalf("project count = %d, want 0", count)
	}
	assertAuditEvent(t, conn, "inventory.project.delete", projectID, `"deleted_asset_count":1`)
}

func newProjectUserRouter(t *testing.T, conn httpDB, now time.Time) (http.Handler, *httptest.ResponseRecorder) {
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
	router := NewRouter(config.Settings{SessionIdleTimeoutMinutes: 30, SessionAbsoluteTimeoutMinutes: 480, LocalAuthEnabled: true}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d; body = %s", loginResponse.Code, http.StatusOK, loginResponse.Body.String())
	}
	return router, loginResponse
}

func authedProjectRequest(t *testing.T, router http.Handler, loginResponse *httptest.ResponseRecorder, method string, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)
	return response
}

type httpProjectFixture struct {
	ID                                string
	Slug                              string
	Name                              string
	Description                       *string
	SLATrackingEnabled                bool
	SLAReportingEnabled               bool
	RequirePeerReviewForStatusChanges bool
	GracePeriodEnabled                bool
	GracePeriodPercent                int
	CreatedAt                         time.Time
	UpdatedAt                         time.Time
}

func insertHTTPProject(t *testing.T, conn httpDB, fixture httpProjectFixture) string {
	t.Helper()
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO projects (
		id, slug, name, description, sla_tracking_enabled, sla_reporting_enabled,
		require_peer_review_for_status_changes, grace_period_enabled, grace_period_percent,
		critical_sla_days, high_sla_days, medium_sla_days, low_sla_days, unknown_sla_days,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 30, 60, 90, 180, 365, ?, ?)`,
		fixture.ID,
		fixture.Slug,
		fixture.Name,
		fixture.Description,
		fixture.SLATrackingEnabled,
		fixture.SLAReportingEnabled,
		fixture.RequirePeerReviewForStatusChanges,
		fixture.GracePeriodEnabled,
		fixture.GracePeriodPercent,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	return fixture.ID
}

type httpAssetNodeFixture struct {
	ID           string
	ProjectID    string
	ParentID     *string
	NodeType     string
	Name         string
	Path         string
	TargetRef    *string
	MetadataJSON string
	SortOrder    int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func insertHTTPAssetNode(t *testing.T, conn httpDB, fixture httpAssetNodeFixture) {
	t.Helper()
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO asset_nodes (
		id, project_id, parent_id, node_type, name, path, target_ref, metadata_json,
		sla_tracking_enabled, sla_reporting_enabled, grace_period_enabled, grace_period_percent,
		sort_order, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?, ?)`,
		fixture.ID,
		fixture.ProjectID,
		fixture.ParentID,
		fixture.NodeType,
		fixture.Name,
		fixture.Path,
		fixture.TargetRef,
		fixture.MetadataJSON,
		fixture.SortOrder,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert asset node: %v", err)
	}
}

func assertAuditEvent(t *testing.T, conn httpDB, eventType string, targetID string, metadataContains string) {
	t.Helper()
	var metadataJSON string
	if err := conn.QueryRowContext(t.Context(), "SELECT metadata_json FROM audit_log_events WHERE event_type = ? AND target_id = ?", eventType, targetID).Scan(&metadataJSON); err != nil {
		t.Fatalf("select audit event %s/%s: %v", eventType, targetID, err)
	}
	if !strings.Contains(metadataJSON, metadataContains) {
		t.Fatalf("metadata_json = %s, want containing %s", metadataJSON, metadataContains)
	}
}
