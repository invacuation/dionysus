package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestFindingsListReturnsImportedTrivyRows(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID, "scan_started_at": "2026-05-07T09:30:00Z"}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/findings?project_id="+projectID+"&sort=package&direction=asc", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body findingListResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Rows) != 2 {
		t.Fatalf("row count = %d, want 2", len(body.Rows))
	}
	row := body.Rows[0]
	if row.ProjectID != projectID || row.ProjectName != "Alpha" || row.ScanTargetID != targetID || row.ScanTargetName != "Production Image" {
		t.Fatalf("row context = %#v", row)
	}
	if row.Scanner != "trivy" || row.PrimaryIdentifier != "CVE-2026-1001" || row.PackageName == nil || *row.PackageName != "openssl" {
		t.Fatalf("finding row = %#v", row)
	}
	if row.FixedVersion == nil || *row.FixedVersion != "3.0.13-1" || row.Severity != "CRITICAL" || row.Status != "open" {
		t.Fatalf("finding fields = %#v", row)
	}
	if row.CVSS["nvd"] == nil || len(row.AdditionalIdentifiers) != 3 || !row.SLAActive || row.SLAStatus != "active" {
		t.Fatalf("derived fields = %#v", row)
	}
}

func TestFindingDetailReturnsEvidenceAndGroup(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID, "scan_started_at": "2026-05-07T09:30:00Z"}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	findingID := findingIDByPackage(t, conn, projectID, "openssl")

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/findings/"+findingID, "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body findingDetailResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ID != findingID || body.ScannerFindingID != "CVE-2026-1001:openssl:3.0.11-1" || body.DedupeKey == "" {
		t.Fatalf("detail identity = %#v", body)
	}
	if len(body.Identifiers) != 4 || len(body.References) != 3 || body.Description == nil || *body.Description != "A representative OpenSSL vulnerability." {
		t.Fatalf("detail evidence = %#v", body)
	}
	if body.ProjectGroup == nil || body.ProjectGroup.PrimaryIdentifier != "CVE-2026-1001" || body.ProjectGroup.Status != "open" {
		t.Fatalf("project group = %#v", body.ProjectGroup)
	}
	if len(body.Comments) != 0 || len(body.StatusChangeRequests) != 0 {
		t.Fatalf("activity = comments %#v requests %#v", body.Comments, body.StatusChangeRequests)
	}
}

func TestFindingsListFiltersByFolderAsset(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "asset-docs", ProjectID: projectID, NodeType: "scan_target", Name: "Docs Image", Path: "docs/Docs Image", TargetRef: ptr("registry.example.test/dionysus/docs:2026.05.07"), MetadataJSON: "{}", SortOrder: 1, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	for _, scanTargetID := range []string{targetID, "asset-docs"} {
		importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": scanTargetID}, trivyFixture(t))
		if importResponse.Code != http.StatusOK {
			t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
		}
	}

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/findings?asset_id=asset-images", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body findingListResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Rows) != 2 {
		t.Fatalf("row count = %d, want 2", len(body.Rows))
	}
	for _, row := range body.Rows {
		if row.ScanTargetID != targetID {
			t.Fatalf("unexpected target in asset filter: %#v", row)
		}
	}
}

func findingIDByPackage(t *testing.T, conn httpDB, projectID string, packageName string) string {
	t.Helper()
	var id string
	if err := conn.QueryRowContext(t.Context(), "SELECT id FROM raw_finding_instances WHERE project_id = ? AND package_name = ?", projectID, packageName).Scan(&id); err != nil {
		t.Fatalf("select finding id: %v", err)
	}
	return id
}
