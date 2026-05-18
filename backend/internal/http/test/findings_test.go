package httpapi_test

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

func TestFindingCommentCreateAppearsInDetailAndAudits(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-comment", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:comment", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	findingID := findingIDByPackage(t, conn, projectID, "openssl")

	response := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/findings/"+findingID+"/comments", `{"body":"  Needs owner validation.  "}`)
	detail := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/findings/"+findingID, "")

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var created findingCommentResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if created.Body != "Needs owner validation." || created.AuthorDisplay == nil || *created.AuthorDisplay != "Alice" || created.IsSystem {
		t.Fatalf("created comment = %#v", created)
	}
	var body findingDetailResponse
	if err := json.NewDecoder(detail.Body).Decode(&body); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if len(body.Comments) != 1 || body.Comments[0].ID != created.ID || body.Comments[0].Body != "Needs owner validation." {
		t.Fatalf("detail comments = %#v", body.Comments)
	}
	assertAuditEvent(t, conn, "finding.comment.created", findingID, `"comment_id":"`+created.ID+`"`)
}

func TestFindingStatusChangeUpdatesFindingGroupActivityAndAudit(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-status", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:status_change:request", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	findingID := findingIDByPackage(t, conn, projectID, "openssl")

	response := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/findings/"+findingID+"/status", `{"status":"fixed","comment":"Patched in image 2026.05.08."}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body findingDetailResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "fixed" || body.ProjectGroup == nil || body.ProjectGroup.Status != "fixed" {
		t.Fatalf("status detail = %#v", body)
	}
	if len(body.Comments) != 1 || body.Comments[0].StatusFrom == nil || *body.Comments[0].StatusFrom != "open" || body.Comments[0].StatusTo == nil || *body.Comments[0].StatusTo != "fixed" {
		t.Fatalf("comments = %#v", body.Comments)
	}
	if len(body.StatusChangeRequests) != 1 || body.StatusChangeRequests[0].State != "approved" {
		t.Fatalf("requests = %#v", body.StatusChangeRequests)
	}
	assertAuditEvent(t, conn, "finding.status.changed", findingID, `"to_status":"fixed"`)
}

func TestFindingStatusPeerReviewApproveAndSelfReviewBlock(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-status", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:status_change:request", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-approve-self", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:status_change:approve", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	findingID := findingIDByPackage(t, conn, projectID, "openssl")
	requestResponse := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/findings/"+findingID+"/status", `{"status":"fixed","comment":"Please review.","require_peer_review":true}`)
	var requested findingDetailResponse
	if err := json.NewDecoder(requestResponse.Body).Decode(&requested); err != nil {
		t.Fatalf("decode requested: %v", err)
	}
	requestID := requested.StatusChangeRequests[0].ID

	selfReview := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/findings/"+findingID+"/status-requests/"+requestID+"/approve", `{"comment":"Looks good."}`)

	if selfReview.Code != http.StatusBadRequest {
		t.Fatalf("self review status = %d, want %d; body = %s", selfReview.Code, http.StatusBadRequest, selfReview.Body.String())
	}
	insertHTTPUser(t, conn, httpUserFixture{ID: "user-2", Username: "bob", DisplayName: "Bob", IsActive: true, PasswordHash: argon2PasswordHash, CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-approve-bob", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-2", Permission: "finding:status_change:approve", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	bobLogin := loginNamedHTTPUser(t, router, "bob", "correct horse battery staple")
	response := authedProjectRequest(t, router, bobLogin, http.MethodPost, "/api/findings/"+findingID+"/status-requests/"+requestID+"/approve", `{"comment":"Looks good."}`)

	if response.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var approved findingDetailResponse
	if err := json.NewDecoder(response.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approved: %v", err)
	}
	if approved.Status != "fixed" || approved.StatusChangeRequests[0].ReviewerDisplay == nil || *approved.StatusChangeRequests[0].ReviewerDisplay != "Bob" {
		t.Fatalf("approved = %#v", approved)
	}
}

func TestReleaseInheritanceAppliesPriorSemverDecisionOnImport(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodEnabled: true, GracePeriodPercent: 50, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "release-scope", ProjectID: projectID, NodeType: "folder", Name: "releases", Path: "releases", MetadataJSON: `{"release_inheritance_scope":true}`, SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "release-4001", ProjectID: projectID, ParentID: ptr("release-scope"), NodeType: "folder", Name: "40.0.1", Path: "releases/40.0.1", MetadataJSON: `{"release_version":"40.0.1"}`, SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "release-4002", ProjectID: projectID, ParentID: ptr("release-scope"), NodeType: "folder", Name: "40.0.2", Path: "releases/40.0.2", MetadataJSON: `{"release_version":"40.0.2"}`, SortOrder: 1, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "target-4001", ProjectID: projectID, ParentID: ptr("release-4001"), NodeType: "scan_target", Name: "api-40.0.1", Path: "releases/40.0.1/images/api", TargetRef: ptr("registry.example.test/api:40.0.1"), MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: "target-4002", ProjectID: projectID, ParentID: ptr("release-4002"), NodeType: "scan_target", Name: "api-40.0.2", Path: "releases/40.0.2/images/api", TargetRef: ptr("registry.example.test/api:40.0.2"), MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-status", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:status_change:request", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "finding-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "finding:view", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	importOne := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": "target-4001"}, trivyFixture(t))
	if importOne.Code != http.StatusOK {
		t.Fatalf("first import status = %d, want %d; body = %s", importOne.Code, http.StatusOK, importOne.Body.String())
	}
	firstFindingID := findingIDByPackage(t, conn, projectID, "openssl")
	statusResponse := authedProjectRequest(t, router, loginResponse, http.MethodPost, "/api/findings/"+firstFindingID+"/status", `{"status":"mitigated","comment":"Mitigated for release line."}`)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status change = %d, want %d; body = %s", statusResponse.Code, http.StatusOK, statusResponse.Body.String())
	}

	importTwo := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": "target-4002"}, trivyFixture(t))

	if importTwo.Code != http.StatusOK {
		t.Fatalf("second import status = %d, want %d; body = %s", importTwo.Code, http.StatusOK, importTwo.Body.String())
	}
	var status string
	if err := conn.QueryRowContext(t.Context(), "SELECT status FROM raw_finding_instances WHERE scan_target_id = ? AND package_name = ?", "target-4002", "openssl").Scan(&status); err != nil {
		t.Fatalf("select inherited finding: %v", err)
	}
	if status != "mitigated" {
		t.Fatalf("inherited status = %q, want mitigated", status)
	}
	var systemComment string
	if err := conn.QueryRowContext(t.Context(), "SELECT body FROM finding_comments WHERE author_principal_type = 'machine' AND author_principal_id = 'system'").Scan(&systemComment); err != nil {
		t.Fatalf("select system comment: %v", err)
	}
	if systemComment != "Inherited mitigated from releases/40.0.1." {
		t.Fatalf("system comment = %q", systemComment)
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
