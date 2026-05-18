package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

type overviewResponse struct {
	OpenFindings        int                          `json:"open_findings"`
	OverdueSLA          int                          `json:"overdue_sla"`
	GracePeriodRisk     int                          `json:"grace_period_risk"`
	SeverityCounts      []overviewSeverityCount      `json:"severity_counts"`
	HighestRiskProjects []overviewProjectRiskSummary `json:"highest_risk_projects"`
}

type overviewSeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type overviewProjectRiskSummary struct {
	ProjectID    string `json:"project_id"`
	ProjectName  string `json:"project_name"`
	OpenCount    int    `json:"open_count"`
	OverdueCount int    `json:"overdue_count"`
}

func mountOverviewRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		handleOverview(w, r, settings, deps)
	})
}

func handleOverview(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "report:view"}); !ok {
		return
	}

	rows, err := dbgen.New(deps.DB).ListFindingRows(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Unable to load overview data!")
		return
	}

	response := overviewFromFindingRows(rows)
	writeJSON(w, http.StatusOK, response)
}


func overviewFromFindingRows(rows []dbgen.ListFindingRowsRow) overviewResponse {
	severityCounts := map[string]int{}
	projectCounts := map[string]overviewProjectRiskSummary{}
	overdueSLA := 0
	gracePeriodRisk := 0

	for _, row := range rows {
		if row.Status != "open" {
			continue
		}

		severityCounts[titleSeverity(row.Severity)]++
		sla := slaStateFromFindingRow(row)
		isOverdue := sla.includeInReports && sla.remainingDays != nil && *sla.remainingDays < 0
		isGraceOverdue := sla.includeInReports && sla.graceRemainingDays != nil && *sla.graceRemainingDays < 0
		if isOverdue {
			overdueSLA++
		}
		if isGraceOverdue {
			gracePeriodRisk++
		}

		current := projectCounts[row.ProjectID]
		current.ProjectID = row.ProjectID
		current.ProjectName = row.ProjectName
		current.OpenCount++
		if isOverdue {
			current.OverdueCount++
		}
		projectCounts[row.ProjectID] = current
	}

	severities := make([]overviewSeverityCount, 0, len(severityCounts))
	for severity, count := range severityCounts {
		severities = append(severities, overviewSeverityCount{Severity: severity, Count: count})
	}
	sort.Slice(severities, func(i, j int) bool {
		return severities[i].Severity < severities[j].Severity
	})

	projects := make([]overviewProjectRiskSummary, 0, len(projectCounts))
	for _, project := range projectCounts {
		projects = append(projects, project)
	}
	sort.Slice(projects, func(i, j int) bool {
		left := projects[i]
		right := projects[j]
		if left.OverdueCount != right.OverdueCount {
			return left.OverdueCount > right.OverdueCount
		}
		if left.OpenCount != right.OpenCount {
			return left.OpenCount > right.OpenCount
		}
		return strings.ToLower(left.ProjectName) > strings.ToLower(right.ProjectName)
	})
	if len(projects) > 5 {
		projects = projects[:5]
	}

	return overviewResponse{
		OpenFindings:        sumSeverityCounts(severities),
		OverdueSLA:          overdueSLA,
		GracePeriodRisk:     gracePeriodRisk,
		SeverityCounts:      severities,
		HighestRiskProjects: projects,
	}
}

func titleSeverity(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	return strings.ToUpper(normalized[:1]) + normalized[1:]
}

func sumSeverityCounts(rows []overviewSeverityCount) int {
	total := 0
	for _, row := range rows {
		total += row.Count
	}
	return total
}
