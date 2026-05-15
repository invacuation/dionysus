package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestProjectAssetsListRequiresViewPermission(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "asset-folder", ProjectID: projectID, NodeType: "folder", Name: "images", Path: "images", MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "project-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "project:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/projects/"+projectID+"/assets", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body projectAssetsResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ProjectID != projectID || len(body.Assets) != 1 || body.Assets[0].Path != "images" {
		t.Fatalf("assets response = %#v", body)
	}
}

func TestFolderResolveCreatesMissingFoldersAndAudits(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "asset-create", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "asset:create", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects/"+projectID+"/folders", `{"path":" images / releases "}`)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var body assetResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Path != "images/releases" || body.Type != "folder" || body.ParentID == nil {
		t.Fatalf("folder = %#v", body)
	}
	assertAuditEvent(t, conn, "inventory.folder.resolve", body.ID, `"path":"images/releases"`)
}

func TestScanTargetCreateAssetUpdateAndDelete(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	for _, permission := range []string{"asset:create", "asset:update", "asset:delete"} {
		insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: permission, PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: permission, Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	}

	createResponse := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects/"+projectID+"/scan-targets", `{"folder_path":"images/releases","name":"Production Image","target_ref":"registry.example.test/app:2026.05"}`)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", createResponse.Code, http.StatusCreated, createResponse.Body.String())
	}
	var created assetResponse
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Path != "images/releases/Production Image" || created.TargetRef == nil || *created.TargetRef != "registry.example.test/app:2026.05" {
		t.Fatalf("created target = %#v", created)
	}

	archiveResponse := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects/"+projectID+"/folders", `{"path":"archive"}`)
	if archiveResponse.Code != http.StatusCreated {
		t.Fatalf("archive status = %d, want %d; body = %s", archiveResponse.Code, http.StatusCreated, archiveResponse.Body.String())
	}
	var archive assetResponse
	if err := json.NewDecoder(archiveResponse.Body).Decode(&archive); err != nil {
		t.Fatalf("decode archive response: %v", err)
	}
	updateBody := `{"name":"Renamed Image","parent_id":"` + archive.ID + `","sla_tracking_enabled":false,"sla_reporting_enabled":true,"grace_period_enabled":true,"grace_period_percent":50}`
	updateResponse := authedProjectRequest(t, router, loginResponse, http.MethodPatch, "/api/projects/"+projectID+"/assets/"+created.ID, updateBody)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update status = %d, want %d; body = %s", updateResponse.Code, http.StatusOK, updateResponse.Body.String())
	}
	var updated assetResponse
	if err := json.NewDecoder(updateResponse.Body).Decode(&updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Path != "archive/Renamed Image" || updated.SLATrackingEnabled == nil || *updated.SLATrackingEnabled || updated.GracePeriodPercent == nil || *updated.GracePeriodPercent != 50 {
		t.Fatalf("updated asset = %#v", updated)
	}

	deleteResponse := authedProjectRequest(t, router, loginResponse, http.MethodDelete, "/api/projects/"+projectID+"/assets/"+archive.ID, "")
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d; body = %s", deleteResponse.Code, http.StatusNoContent, deleteResponse.Body.String())
	}
	var remaining int
	if err := conn.QueryRowContext(t.Context(), "SELECT count(*) FROM asset_nodes WHERE project_id = ? AND path LIKE 'archive%'", projectID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining archive assets: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining archive assets = %d, want 0", remaining)
	}
}

func TestFolderResolveRejectsInvalidPath(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "asset-create", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "asset:create", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/projects/"+projectID+"/folders", `{"path":"images//releases"}`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "folder path must not contain empty segments") {
		t.Fatalf("body = %s", response.Body.String())
	}
}
