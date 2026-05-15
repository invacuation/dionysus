package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestTrivyPreviewReturnsDetectedMetadataWithoutPersistence(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	_ = targetID
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy/preview", map[string]string{"project_id": projectID}, trivyFixture(t))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body trivyPreviewResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Scanner != "trivy" || body.ReportKind != "trivy-image-json" || body.FindingCount != 2 || body.GroupCount != 2 {
		t.Fatalf("preview = %#v", body)
	}
	if body.DetectedProjectName != "api" || body.DetectedAssetName != "2026.05.07" || body.DetectedTargetRef != "registry.example.test/dionysus/api:2026.05.07" {
		t.Fatalf("detected defaults = %#v", body)
	}
	assertTableCount(t, conn, "import_attempts", 0)
	assertTableCount(t, conn, "scans", 0)
	assertTableCount(t, conn, "raw_finding_instances", 0)
}

func TestTrivyImportPersistsScanFindingsAndAudit(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID, "scan_started_at": "2026-05-07T09:30:00+00:00"}, trivyFixture(t))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body trivyImportResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ProjectID != projectID || body.ScanTargetID != targetID || body.FindingCount != 2 || body.GroupCount != 2 {
		t.Fatalf("import response = %#v", body)
	}
	assertTableCount(t, conn, "import_attempts", 1)
	assertTableCount(t, conn, "scans", 1)
	assertTableCount(t, conn, "raw_finding_instances", 2)
	assertAuditEvent(t, conn, "import.trivy.success", targetID, `"finding_count":2`)
}

func TestTrivyImportInvalidJSONRecordsFailedAttempt(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})

	response := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID}, []byte(`{"ArtifactName":"secret-registry.example.test/private:latest",`))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	assertJSONDetail(t, response, "invalid JSON: unable to parse Trivy report")
	if strings.Contains(response.Body.String(), "secret-registry") {
		t.Fatalf("response leaked report content: %s", response.Body.String())
	}
	assertTableCount(t, conn, "import_attempts", 1)
	assertTableCount(t, conn, "scans", 0)
	assertTableCount(t, conn, "raw_finding_instances", 0)
	assertAuditEvent(t, conn, "import.trivy.failure", targetID, `"failure_category":"parser_error"`)
}

func TestAdminImportHistoryReturnsSanitizedAttempts(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-history", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:history:view", Effect: identity.PermissionEffectAllow, CreatedAt: now, UpdatedAt: now})
	insertHTTPImportAttempt(t, conn, httpImportAttemptFixture{
		ID:                    "attempt-1",
		ProjectID:             projectID,
		AssetNodeID:           ptr(targetID),
		UploaderPrincipalType: ptr("user"),
		UploaderPrincipalID:   ptr("user-1"),
		Status:                "success",
		ParserName:            "trivy-image-json",
		SanitizedMessage:      ptr("import completed"),
		CorrelationID:         ptr("corr-1"),
		MetadataJSON:          `{"scanner":"trivy","finding_count":2,"secret_path":"/tmp/private-report.json"}`,
		CreatedAt:             now,
		UpdatedAt:             now,
	})

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/admin/imports?limit=999", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body adminImportHistoryResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Attempts) != 1 {
		t.Fatalf("attempt count = %d, want 1", len(body.Attempts))
	}
	attempt := body.Attempts[0]
	if attempt.ID != "attempt-1" || attempt.ProjectName != "Alpha" || attempt.AssetID == nil || *attempt.AssetID != targetID {
		t.Fatalf("attempt = %#v", attempt)
	}
	if attempt.UploaderDisplay == nil || *attempt.UploaderDisplay != "Alice" {
		t.Fatalf("uploader display = %#v", attempt.UploaderDisplay)
	}
	if attempt.Metadata["scanner"] != "trivy" || attempt.Metadata["finding_count"] == nil {
		t.Fatalf("metadata missing allowed values: %#v", attempt.Metadata)
	}
	if _, exists := attempt.Metadata["secret_path"]; exists {
		t.Fatalf("metadata leaked disallowed value: %#v", attempt.Metadata)
	}
}

func newImportProjectFixture(t *testing.T, conn httpDB, now time.Time) (string, string) {
	t.Helper()
	projectID := insertHTTPProject(t, conn, httpProjectFixture{ID: "project-alpha", Slug: "alpha", Name: "Alpha", SLATrackingEnabled: true, SLAReportingEnabled: true, GracePeriodPercent: 100, CreatedAt: now, UpdatedAt: now})
	folderID := "asset-images"
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: folderID, ProjectID: projectID, NodeType: "folder", Name: "images", Path: "images", MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	targetID := "asset-target"
	insertHTTPAssetNode(t, conn, httpAssetNodeFixture{ID: targetID, ProjectID: projectID, ParentID: &folderID, NodeType: "scan_target", Name: "Production Image", Path: "images/Production Image", TargetRef: ptr("registry.example.test/dionysus/api:2026.05.07"), MetadataJSON: "{}", SortOrder: 0, CreatedAt: now, UpdatedAt: now})
	return projectID, targetID
}

func trivyFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "python", "tests", "fixtures", "trivy-image.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return payload
}

func authedMultipartRequest(t *testing.T, router http.Handler, loginResponse *httptest.ResponseRecorder, target string, fields map[string]string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write field %s: %v", key, err)
		}
	}
	part, err := writer.CreateFormFile("report_file", "trivy-image.json")
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, target, &requestBody)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)
	return response
}

func assertTableCount(t *testing.T, conn httpDB, table string, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}

type httpImportAttemptFixture struct {
	ID                    string
	ProjectID             string
	AssetNodeID           *string
	UploaderPrincipalType *string
	UploaderPrincipalID   *string
	Status                string
	ParserName            string
	SanitizedMessage      *string
	CorrelationID         *string
	MetadataJSON          string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

func insertHTTPImportAttempt(t *testing.T, conn httpDB, fixture httpImportAttemptFixture) {
	t.Helper()
	if _, err := conn.ExecContext(t.Context(), `INSERT INTO import_attempts (
		id,
		project_id,
		asset_node_id,
		uploader_principal_type,
		uploader_principal_id,
		status,
		parser_name,
		sanitized_message,
		correlation_id,
		metadata_json,
		created_at,
		updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.ProjectID,
		fixture.AssetNodeID,
		fixture.UploaderPrincipalType,
		fixture.UploaderPrincipalID,
		fixture.Status,
		fixture.ParserName,
		fixture.SanitizedMessage,
		fixture.CorrelationID,
		fixture.MetadataJSON,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert import attempt: %v", err)
	}
}
