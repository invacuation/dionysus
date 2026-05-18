package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestOverviewReturnsEstateMetricsForReportViewer(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	projectID, targetID := newImportProjectFixture(t, conn, now)
	if _, err := conn.ExecContext(context.Background(), `UPDATE projects SET grace_period_enabled = TRUE, grace_period_percent = 50 WHERE id = ?`, projectID); err != nil {
		t.Fatalf("enable project grace period: %v", err)
	}
	router, loginResponse := newProjectUserRouter(t, conn, now)
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "import-upload", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "import:upload", Effect: identity.PermissionEffectAllow, ScopeType: ptr("project"), ScopeID: ptr(projectID), CreatedAt: now, UpdatedAt: now})
	insertScopedHTTPPermission(t, conn, httpScopedPermissionFixture{ID: "report-view", PrincipalType: identity.PrincipalTypeUser, PrincipalID: "user-1", Permission: "report:view", Effect: identity.PermissionEffectAllow, CreatedAt: now, UpdatedAt: now})

	importResponse := authedMultipartRequest(t, router, loginResponse, "/api/imports/trivy", map[string]string{"project_id": projectID, "scan_target_id": targetID}, trivyFixture(t))
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	oldSeenAt := time.Date(2023, 1, 1, 9, 0, 0, 0, time.UTC)
	if _, err := conn.ExecContext(context.Background(), `UPDATE raw_finding_instances SET first_seen_at = ?, last_seen_at = ? WHERE project_id = ?`, oldSeenAt, oldSeenAt, projectID); err != nil {
		t.Fatalf("age findings: %v", err)
	}

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/overview", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body struct {
		OpenFindings    int `json:"open_findings"`
		OverdueSLA      int `json:"overdue_sla"`
		GracePeriodRisk int `json:"grace_period_risk"`
		SeverityCounts  []struct {
			Severity string `json:"severity"`
			Count    int    `json:"count"`
		} `json:"severity_counts"`
		HighestRiskProjects []struct {
			ProjectID    string `json:"project_id"`
			ProjectName  string `json:"project_name"`
			OpenCount    int    `json:"open_count"`
			OverdueCount int    `json:"overdue_count"`
		} `json:"highest_risk_projects"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OpenFindings != 2 || body.OverdueSLA != 2 || body.GracePeriodRisk != 2 {
		t.Fatalf("overview counts = %#v, want 2 open, 2 overdue, 2 grace risk", body)
	}
	if len(body.SeverityCounts) != 2 {
		t.Fatalf("severity count rows = %d, want 2: %#v", len(body.SeverityCounts), body.SeverityCounts)
	}
	if body.SeverityCounts[0].Severity != "Critical" || body.SeverityCounts[0].Count != 1 {
		t.Fatalf("first severity count = %#v, want Critical/1", body.SeverityCounts[0])
	}
	if body.SeverityCounts[1].Severity != "Medium" || body.SeverityCounts[1].Count != 1 {
		t.Fatalf("second severity count = %#v, want Medium/1", body.SeverityCounts[1])
	}
	if len(body.HighestRiskProjects) != 1 {
		t.Fatalf("project risk rows = %d, want 1: %#v", len(body.HighestRiskProjects), body.HighestRiskProjects)
	}
	project := body.HighestRiskProjects[0]
	if project.ProjectID != projectID || project.ProjectName != "Alpha" || project.OpenCount != 2 || project.OverdueCount != 2 {
		t.Fatalf("project risk = %#v, want Alpha with 2 open and 2 overdue", project)
	}
}

func TestOverviewRequiresReportPermission(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	router, loginResponse := newProjectUserRouter(t, conn, now)

	response := authedProjectRequest(t, router, loginResponse, http.MethodGet, "/api/overview", "")

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
	assertJSONDetail(t, response, "Forbidden")
}
