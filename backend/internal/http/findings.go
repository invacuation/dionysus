package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

var findingStatuses = map[string]bool{
	"open":           true,
	"accepted_risk":  true,
	"false_positive": true,
	"mitigated":      true,
	"suppressed":     true,
	"fixed":          true,
}

var findingSortKeys = map[string]bool{
	"severity":          true,
	"first_detected":    true,
	"last_seen":         true,
	"package":           true,
	"installed_version": true,
	"fixed_version":     true,
	"identifier":        true,
	"project":           true,
	"status":            true,
	"sla_remaining":     true,
	"grace_remaining":   true,
}

type findingListResponse struct {
	Rows []findingRowResponse `json:"rows"`
}

type findingRowResponse struct {
	ID                    string         `json:"id"`
	ProjectID             string         `json:"project_id"`
	ProjectName           string         `json:"project_name"`
	ScanTargetID          string         `json:"scan_target_id"`
	ScanTargetName        string         `json:"scan_target_name"`
	ScanTargetPath        string         `json:"scan_target_path"`
	ScanTargetRef         *string        `json:"scan_target_ref"`
	Scanner               string         `json:"scanner"`
	PrimaryIdentifier     string         `json:"primary_identifier"`
	AdditionalIdentifiers []string       `json:"additional_identifiers"`
	PackageName           *string        `json:"package_name"`
	InstalledVersion      *string        `json:"installed_version"`
	FixedVersion          *string        `json:"fixed_version"`
	Severity              string         `json:"severity"`
	CVSS                  map[string]any `json:"cvss"`
	Status                string         `json:"status"`
	FirstDetectedAt       time.Time      `json:"first_detected_at"`
	LastSeenAt            time.Time      `json:"last_seen_at"`
	PresentInLatestScan   bool           `json:"present_in_latest_scan"`
	SLAActive             bool           `json:"sla_active"`
	SLARemainingDays      *int           `json:"sla_remaining_days"`
	GraceRemainingDays    *int           `json:"grace_remaining_days"`
	SLAStatus             string         `json:"sla_status"`
	SLAReason             *string        `json:"sla_reason"`
	SLADays               *int           `json:"sla_days"`
	GraceDays             *int           `json:"grace_days"`
	IncludeInSLAReports   bool           `json:"include_in_sla_reports"`
}

type findingDetailResponse struct {
	findingRowResponse
	ScannerFindingID     string                               `json:"scanner_finding_id"`
	DedupeKey            string                               `json:"dedupe_key"`
	Identifiers          []string                             `json:"identifiers"`
	References           []string                             `json:"references"`
	Description          *string                              `json:"description"`
	ArtifactName         *string                              `json:"artifact_name"`
	ArtifactType         *string                              `json:"artifact_type"`
	ArtifactPath         *string                              `json:"artifact_path"`
	SourceEvidence       map[string]any                       `json:"source_evidence"`
	ProjectGroup         *projectGroupResponse                `json:"project_group"`
	Comments             []findingCommentResponse             `json:"comments"`
	StatusChangeRequests []findingStatusChangeRequestResponse `json:"status_change_requests"`
}

type projectGroupResponse struct {
	ID                    string    `json:"id"`
	PrimaryIdentifier     string    `json:"primary_identifier"`
	AdditionalIdentifiers []string  `json:"additional_identifiers"`
	Status                string    `json:"status"`
	FirstDetectedAt       time.Time `json:"first_detected_at"`
}

type findingCommentResponse struct {
	ID                  string    `json:"id"`
	Body                string    `json:"body"`
	AuthorPrincipalType string    `json:"author_principal_type"`
	AuthorPrincipalID   string    `json:"author_principal_id"`
	AuthorDisplay       *string   `json:"author_display"`
	CreatedAt           time.Time `json:"created_at"`
	IsSystem            bool      `json:"is_system"`
	StatusFrom          *string   `json:"status_from"`
	StatusTo            *string   `json:"status_to"`
}

type findingStatusChangeRequestResponse struct {
	ID                     string     `json:"id"`
	RequesterPrincipalType string     `json:"requester_principal_type"`
	RequesterPrincipalID   string     `json:"requester_principal_id"`
	RequesterDisplay       *string    `json:"requester_display"`
	ReviewerPrincipalType  *string    `json:"reviewer_principal_type"`
	ReviewerPrincipalID    *string    `json:"reviewer_principal_id"`
	ReviewerDisplay        *string    `json:"reviewer_display"`
	FromStatus             string     `json:"from_status"`
	ToStatus               string     `json:"to_status"`
	State                  string     `json:"state"`
	Comment                *string    `json:"comment"`
	DecisionComment        *string    `json:"decision_comment"`
	CreatedAt              time.Time  `json:"created_at"`
	DecidedAt              *time.Time `json:"decided_at"`
}

type findingRowData struct {
	dbgen.ListFindingRowsRow
}

type findingFilters struct {
	ProjectID           string
	ScanTargetID        string
	AssetID             string
	Scanner             string
	Severity            string
	Identifier          string
	Package             string
	Status              string
	PresentInLatestScan *bool
	FixAvailable        *bool
	Sort                string
	Direction           string
}

func mountFindingRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		listFindings(w, r, settings, deps)
	})
	router.Get("/api/findings/{findingID}", func(w http.ResponseWriter, r *http.Request) {
		getFindingDetail(w, r, settings, deps)
	})
}

func listFindings(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := authenticatedActorFromRequest(w, r, settings, deps)
	if !ok {
		return
	}
	filters, ok := parseFindingFilters(w, r)
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	rows, err := queries.ListFindingRows(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	assetScanTargetIDs, err := findingAssetScanTargetIDs(r, queries, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	visible := make([]dbgen.ListFindingRowsRow, 0, len(rows))
	for _, row := range rows {
		if !findingMatchesFilters(row, filters, assetScanTargetIDs) {
			continue
		}
		if _, err := identity.EnsureActorPermission(r.Context(), deps.DB, *actor, identity.PermissionRequest{Permission: "finding:view", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)}); err != nil {
			if errors.Is(err, identity.ErrForbidden) {
				continue
			}
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		visible = append(visible, row)
	}
	sortFindingRows(visible, filters.Sort, filters.Direction)
	responses := make([]findingRowResponse, 0, len(visible))
	for _, row := range visible {
		response, err := findingRowResponseFromDB(row)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		responses = append(responses, response)
	}
	writeJSON(w, http.StatusOK, findingListResponse{Rows: responses})
}

func getFindingDetail(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	findingID := chi.URLParam(r, "findingID")
	queries := dbgen.New(deps.DB)
	row, err := queries.GetFindingRow(r.Context(), findingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Finding not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "finding:view", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)}); !ok {
		return
	}
	response, err := findingDetailResponseFromDB(r, queries, row)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func parseFindingFilters(w http.ResponseWriter, r *http.Request) (findingFilters, bool) {
	query := r.URL.Query()
	status := strings.TrimSpace(query.Get("status"))
	if status != "" && !findingStatuses[status] {
		writeError(w, http.StatusBadRequest, "Unsupported finding status")
		return findingFilters{}, false
	}
	sortKey := strings.TrimSpace(query.Get("sort"))
	if sortKey == "" {
		sortKey = "last_seen"
	}
	if !findingSortKeys[sortKey] {
		writeError(w, http.StatusBadRequest, "Unsupported finding sort")
		return findingFilters{}, false
	}
	direction := strings.TrimSpace(query.Get("direction"))
	if direction == "" {
		direction = "desc"
	}
	if direction != "asc" && direction != "desc" {
		writeError(w, http.StatusBadRequest, "Unsupported finding sort direction")
		return findingFilters{}, false
	}
	present, ok := parseOptionalFindingBool(w, query.Get("present_in_latest_scan"), "present_in_latest_scan")
	if !ok {
		return findingFilters{}, false
	}
	fixAvailable, ok := parseOptionalFindingBool(w, query.Get("fix_available"), "fix_available")
	if !ok {
		return findingFilters{}, false
	}
	return findingFilters{
		ProjectID:           strings.TrimSpace(query.Get("project_id")),
		ScanTargetID:        strings.TrimSpace(query.Get("scan_target_id")),
		AssetID:             strings.TrimSpace(query.Get("asset_id")),
		Scanner:             strings.TrimSpace(query.Get("scanner")),
		Severity:            strings.TrimSpace(query.Get("severity")),
		Identifier:          strings.TrimSpace(query.Get("identifier")),
		Package:             strings.TrimSpace(query.Get("package")),
		Status:              status,
		PresentInLatestScan: present,
		FixAvailable:        fixAvailable,
		Sort:                sortKey,
		Direction:           direction,
	}, true
}

func parseOptionalFindingBool(w http.ResponseWriter, raw string, field string) (*bool, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		value := true
		return &value, true
	case "0", "false", "no", "off":
		value := false
		return &value, true
	default:
		writeError(w, http.StatusBadRequest, field+" must be true or false")
		return nil, false
	}
}

func findingAssetScanTargetIDs(r *http.Request, queries *dbgen.Queries, filters findingFilters) (map[string]bool, error) {
	if filters.AssetID == "" {
		return nil, nil
	}
	asset, err := queries.GetAssetNode(r.Context(), filters.AssetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	if filters.ProjectID != "" && asset.ProjectID != filters.ProjectID {
		return map[string]bool{}, nil
	}
	if asset.NodeType == "scan_target" {
		return map[string]bool{asset.ID: true}, nil
	}
	assets, err := queries.ListProjectAssets(r.Context(), asset.ProjectID)
	if err != nil {
		return nil, err
	}
	byParent := map[string][]dbgen.AssetNode{}
	for _, projectAsset := range assets {
		if projectAsset.ParentID.Valid {
			byParent[projectAsset.ParentID.String] = append(byParent[projectAsset.ParentID.String], projectAsset)
		}
	}
	targetIDs := map[string]bool{}
	stack := []string{asset.ID}
	for len(stack) > 0 {
		parentID := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, child := range byParent[parentID] {
			if child.NodeType == "scan_target" {
				targetIDs[child.ID] = true
			}
			stack = append(stack, child.ID)
		}
	}
	return targetIDs, nil
}

func findingMatchesFilters(row dbgen.ListFindingRowsRow, filters findingFilters, assetScanTargetIDs map[string]bool) bool {
	if filters.ProjectID != "" && row.ProjectID != filters.ProjectID {
		return false
	}
	if filters.ScanTargetID != "" && row.ScanTargetID != filters.ScanTargetID {
		return false
	}
	if assetScanTargetIDs != nil && !assetScanTargetIDs[row.ScanTargetID] {
		return false
	}
	if filters.Scanner != "" && !strings.EqualFold(row.ScannerKind, filters.Scanner) {
		return false
	}
	if filters.Severity != "" && !strings.EqualFold(row.Severity, filters.Severity) {
		return false
	}
	if filters.Package != "" && !strings.Contains(strings.ToLower(optionalStringValue(row.PackageName)), strings.ToLower(filters.Package)) {
		return false
	}
	if filters.Status != "" && row.Status != filters.Status {
		return false
	}
	if filters.PresentInLatestScan != nil && row.PresentInLatestScan != *filters.PresentInLatestScan {
		return false
	}
	if filters.FixAvailable != nil {
		hasFix := strings.TrimSpace(optionalStringValue(row.FixedVersion)) != ""
		if hasFix != *filters.FixAvailable {
			return false
		}
	}
	if filters.Identifier != "" && !findingIdentifierMatches(row, filters.Identifier) {
		return false
	}
	return true
}

func findingIdentifierMatches(row dbgen.ListFindingRowsRow, needle string) bool {
	needle = strings.ToLower(needle)
	candidates := []string{row.PrimaryIdentifier, row.ScannerFindingID, row.DedupeKey, row.IdentifiersJson}
	for _, candidate := range candidates {
		if strings.Contains(strings.ToLower(candidate), needle) {
			return true
		}
	}
	return false
}

func sortFindingRows(rows []dbgen.ListFindingRowsRow, key string, direction string) {
	reverse := direction == "desc"
	sort.SliceStable(rows, func(i, j int) bool {
		cmp := compareFindingRows(rows[i], rows[j], key, direction)
		if reverse && key != "sla_remaining" && key != "grace_remaining" {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareFindingRows(left dbgen.ListFindingRowsRow, right dbgen.ListFindingRowsRow, key string, direction string) int {
	switch key {
	case "severity":
		return compareInts(severityRankForFindings(left.Severity), severityRankForFindings(right.Severity))
	case "first_detected":
		return compareTimes(left.FirstSeenAt, right.FirstSeenAt)
	case "package":
		return strings.Compare(strings.ToLower(optionalStringValue(left.PackageName)), strings.ToLower(optionalStringValue(right.PackageName)))
	case "installed_version":
		return strings.Compare(strings.ToLower(optionalStringValue(left.PackageVersion)), strings.ToLower(optionalStringValue(right.PackageVersion)))
	case "fixed_version":
		return strings.Compare(strings.ToLower(optionalStringValue(left.FixedVersion)), strings.ToLower(optionalStringValue(right.FixedVersion)))
	case "identifier":
		return strings.Compare(strings.ToLower(left.PrimaryIdentifier), strings.ToLower(right.PrimaryIdentifier))
	case "project":
		return strings.Compare(strings.ToLower(left.ProjectName), strings.ToLower(right.ProjectName))
	case "status":
		return strings.Compare(strings.ToLower(left.Status), strings.ToLower(right.Status))
	case "sla_remaining":
		return compareNullableInts(slaStateFromFindingRow(left).remainingDays, slaStateFromFindingRow(right).remainingDays, direction)
	case "grace_remaining":
		return compareNullableInts(slaStateFromFindingRow(left).graceRemainingDays, slaStateFromFindingRow(right).graceRemainingDays, direction)
	default:
		return compareTimes(left.LastSeenAt, right.LastSeenAt)
	}
}

func findingRowResponseFromDB(row dbgen.ListFindingRowsRow) (findingRowResponse, error) {
	cvss := map[string]any{}
	if err := json.Unmarshal([]byte(row.CvssJson), &cvss); err != nil {
		return findingRowResponse{}, err
	}
	identifiers, err := jsonStringSlice(row.IdentifiersJson)
	if err != nil {
		return findingRowResponse{}, err
	}
	sla := slaStateFromFindingRow(row)
	return findingRowResponse{
		ID:                    row.FindingID,
		ProjectID:             row.ProjectID,
		ProjectName:           row.ProjectName,
		ScanTargetID:          row.ScanTargetID,
		ScanTargetName:        row.ScanTargetName,
		ScanTargetPath:        row.ScanTargetPath,
		ScanTargetRef:         optionalStringFromNull(row.ScanTargetRef),
		Scanner:               row.ScannerKind,
		PrimaryIdentifier:     row.PrimaryIdentifier,
		AdditionalIdentifiers: additionalIdentifiers(identifiers, row.PrimaryIdentifier),
		PackageName:           optionalStringFromNull(row.PackageName),
		InstalledVersion:      optionalStringFromNull(row.PackageVersion),
		FixedVersion:          optionalStringFromNull(row.FixedVersion),
		Severity:              row.Severity,
		CVSS:                  cvss,
		Status:                row.Status,
		FirstDetectedAt:       row.FirstSeenAt.UTC(),
		LastSeenAt:            row.LastSeenAt.UTC(),
		PresentInLatestScan:   row.PresentInLatestScan,
		SLAActive:             sla.active,
		SLARemainingDays:      sla.remainingDays,
		GraceRemainingDays:    sla.graceRemainingDays,
		SLAStatus:             sla.status,
		SLAReason:             sla.reason,
		SLADays:               sla.slaDays,
		GraceDays:             sla.graceDays,
		IncludeInSLAReports:   sla.includeInReports,
	}, nil
}

func findingDetailResponseFromDB(r *http.Request, queries *dbgen.Queries, row dbgen.GetFindingRowRow) (findingDetailResponse, error) {
	listRow := listRowFromGetRow(row)
	base, err := findingRowResponseFromDB(listRow)
	if err != nil {
		return findingDetailResponse{}, err
	}
	identifiers, err := jsonStringSlice(row.IdentifiersJson)
	if err != nil {
		return findingDetailResponse{}, err
	}
	references, err := jsonStringSlice(row.ReferencesJson)
	if err != nil {
		return findingDetailResponse{}, err
	}
	source := map[string]any{}
	if err := json.Unmarshal([]byte(row.SourceJson), &source); err != nil {
		return findingDetailResponse{}, err
	}
	comments, err := findingCommentResponses(r, queries, row.FindingID)
	if err != nil {
		return findingDetailResponse{}, err
	}
	statusRequests, err := findingStatusRequestResponses(r, queries, row.FindingID)
	if err != nil {
		return findingDetailResponse{}, err
	}
	return findingDetailResponse{
		findingRowResponse:   base,
		ScannerFindingID:     row.ScannerFindingID,
		DedupeKey:            row.DedupeKey,
		Identifiers:          identifiers,
		References:           references,
		Description:          sourceDescription(source),
		ArtifactName:         optionalStringFromNull(row.ArtifactName),
		ArtifactType:         optionalStringFromNull(row.ArtifactType),
		ArtifactPath:         optionalStringFromNull(row.ArtifactPath),
		SourceEvidence:       source,
		ProjectGroup:         projectGroupResponseFromFinding(row),
		Comments:             comments,
		StatusChangeRequests: statusRequests,
	}, nil
}

func findingCommentResponses(r *http.Request, queries *dbgen.Queries, findingID string) ([]findingCommentResponse, error) {
	rows, err := queries.ListFindingComments(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	responses := make([]findingCommentResponse, 0, len(rows))
	for _, row := range rows {
		responses = append(responses, findingCommentResponse{
			ID:                  row.ID,
			Body:                row.Body,
			AuthorPrincipalType: row.AuthorPrincipalType,
			AuthorPrincipalID:   row.AuthorPrincipalID,
			AuthorDisplay:       firstValidString(row.UserDisplay, row.MachineDisplay),
			CreatedAt:           row.CreatedAt.UTC(),
			IsSystem:            row.IsSystem,
			StatusFrom:          optionalStringFromNull(row.StatusFrom),
			StatusTo:            optionalStringFromNull(row.StatusTo),
		})
	}
	return responses, nil
}

func findingStatusRequestResponses(r *http.Request, queries *dbgen.Queries, findingID string) ([]findingStatusChangeRequestResponse, error) {
	rows, err := queries.ListFindingStatusChangeRequests(r.Context(), findingID)
	if err != nil {
		return nil, err
	}
	responses := make([]findingStatusChangeRequestResponse, 0, len(rows))
	for _, row := range rows {
		responses = append(responses, findingStatusChangeRequestResponse{
			ID:                     row.ID,
			RequesterPrincipalType: row.RequesterPrincipalType,
			RequesterPrincipalID:   row.RequesterPrincipalID,
			RequesterDisplay:       firstValidString(row.RequesterUserDisplay, row.RequesterMachineDisplay),
			ReviewerPrincipalType:  optionalStringFromNull(row.ReviewerPrincipalType),
			ReviewerPrincipalID:    optionalStringFromNull(row.ReviewerPrincipalID),
			ReviewerDisplay:        firstValidString(row.ReviewerUserDisplay, row.ReviewerMachineDisplay),
			FromStatus:             row.FromStatus,
			ToStatus:               row.ToStatus,
			State:                  row.State,
			Comment:                optionalStringFromNull(row.Comment),
			DecisionComment:        optionalStringFromNull(row.DecisionComment),
			CreatedAt:              row.CreatedAt.UTC(),
			DecidedAt:              optionalTimeFromNull(row.DecidedAt),
		})
	}
	return responses, nil
}

func listRowFromGetRow(row dbgen.GetFindingRowRow) dbgen.ListFindingRowsRow {
	return dbgen.ListFindingRowsRow{
		FindingID:                      row.FindingID,
		ProjectID:                      row.ProjectID,
		ProjectName:                    row.ProjectName,
		ScanTargetID:                   row.ScanTargetID,
		ScanTargetName:                 row.ScanTargetName,
		ScanTargetPath:                 row.ScanTargetPath,
		ScanTargetRef:                  row.ScanTargetRef,
		ScannerKind:                    row.ScannerKind,
		ScannerFindingID:               row.ScannerFindingID,
		DedupeKey:                      row.DedupeKey,
		IdentifiersJson:                row.IdentifiersJson,
		PrimaryIdentifier:              row.PrimaryIdentifier,
		Severity:                       row.Severity,
		CvssJson:                       row.CvssJson,
		PackageName:                    row.PackageName,
		PackageVersion:                 row.PackageVersion,
		FixedVersion:                   row.FixedVersion,
		ArtifactName:                   row.ArtifactName,
		ArtifactType:                   row.ArtifactType,
		ArtifactPath:                   row.ArtifactPath,
		FirstSeenAt:                    row.FirstSeenAt,
		LastSeenAt:                     row.LastSeenAt,
		PresentInLatestScan:            row.PresentInLatestScan,
		Status:                         row.Status,
		ReferencesJson:                 row.ReferencesJson,
		SourceJson:                     row.SourceJson,
		SlaTrackingEnabled:             row.SlaTrackingEnabled,
		SlaReportingEnabled:            row.SlaReportingEnabled,
		GracePeriodEnabled:             row.GracePeriodEnabled,
		GracePeriodPercent:             row.GracePeriodPercent,
		CriticalSlaDays:                row.CriticalSlaDays,
		HighSlaDays:                    row.HighSlaDays,
		MediumSlaDays:                  row.MediumSlaDays,
		LowSlaDays:                     row.LowSlaDays,
		UnknownSlaDays:                 row.UnknownSlaDays,
		AssetSlaTrackingEnabled:        row.AssetSlaTrackingEnabled,
		AssetSlaReportingEnabled:       row.AssetSlaReportingEnabled,
		AssetGracePeriodEnabled:        row.AssetGracePeriodEnabled,
		AssetGracePeriodPercent:        row.AssetGracePeriodPercent,
		GroupID:                        row.GroupID,
		GroupPrimaryIdentifier:         row.GroupPrimaryIdentifier,
		GroupAdditionalIdentifiersJson: row.GroupAdditionalIdentifiersJson,
		GroupFirstDetectedAt:           row.GroupFirstDetectedAt,
		GroupStatus:                    row.GroupStatus,
	}
}

type findingSLAState struct {
	active             bool
	remainingDays      *int
	graceRemainingDays *int
	includeInReports   bool
	status             string
	reason             *string
	slaDays            *int
	graceDays          *int
}

func slaStateFromFindingRow(row dbgen.ListFindingRowsRow) findingSLAState {
	includeInReports := row.SlaReportingEnabled
	if row.AssetSlaReportingEnabled.Valid {
		includeInReports = row.AssetSlaReportingEnabled.Bool
	}
	if row.Status != "open" {
		return findingSLAState{status: "not_applicable", reason: stringPtr("finding_not_open")}
	}
	tracking := row.SlaTrackingEnabled
	if row.AssetSlaTrackingEnabled.Valid {
		tracking = row.AssetSlaTrackingEnabled.Bool
	}
	if !tracking {
		return findingSLAState{status: "tracking_disabled", reason: stringPtr("sla_tracking_disabled"), includeInReports: includeInReports}
	}
	slaDays := int(slaDaysForFinding(row))
	dueAt := row.FirstSeenAt.UTC().AddDate(0, 0, slaDays)
	remaining := int(dueAt.Sub(time.Now().UTC()).Hours() / 24)
	graceDays := (*int)(nil)
	graceRemaining := (*int)(nil)
	graceEnabled := row.GracePeriodEnabled
	if row.AssetGracePeriodEnabled.Valid {
		graceEnabled = row.AssetGracePeriodEnabled.Bool
	}
	if graceEnabled {
		percent := row.GracePeriodPercent
		if row.AssetGracePeriodPercent.Valid {
			percent = row.AssetGracePeriodPercent.Int64
		}
		value := maxInt(0, slaDays*int(percent)/100)
		graceDays = &value
		remainingWithGrace := remaining + value
		graceRemaining = &remainingWithGrace
	}
	return findingSLAState{
		active:             true,
		remainingDays:      &remaining,
		graceRemainingDays: graceRemaining,
		includeInReports:   includeInReports,
		status:             "active",
		slaDays:            &slaDays,
		graceDays:          graceDays,
	}
}

func slaDaysForFinding(row dbgen.ListFindingRowsRow) int64 {
	switch strings.ToLower(row.Severity) {
	case "critical":
		return row.CriticalSlaDays
	case "high":
		return row.HighSlaDays
	case "medium":
		return row.MediumSlaDays
	case "low":
		return row.LowSlaDays
	default:
		return row.UnknownSlaDays
	}
}

func projectGroupResponseFromFinding(row dbgen.GetFindingRowRow) *projectGroupResponse {
	if !row.GroupID.Valid {
		return nil
	}
	additional, _ := jsonStringSlice(row.GroupAdditionalIdentifiersJson.String)
	return &projectGroupResponse{
		ID:                    row.GroupID.String,
		PrimaryIdentifier:     row.GroupPrimaryIdentifier.String,
		AdditionalIdentifiers: additional,
		Status:                row.GroupStatus.String,
		FirstDetectedAt:       row.GroupFirstDetectedAt.Time.UTC(),
	}
}

func additionalIdentifiers(identifiers []string, primary string) []string {
	additional := []string{}
	for _, identifier := range identifiers {
		if !strings.EqualFold(identifier, primary) {
			additional = append(additional, identifier)
		}
	}
	return additional
}

func sourceDescription(source map[string]any) *string {
	for _, key := range []string{"description", "title"} {
		if value, ok := source[key].(string); ok && strings.TrimSpace(value) != "" {
			return stringPtr(strings.TrimSpace(value))
		}
	}
	return nil
}

func jsonStringSlice(raw string) ([]string, error) {
	values := []string{}
	if raw == "" {
		return values, nil
	}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func optionalStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func optionalTimeFromNull(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	utc := value.Time.UTC()
	return &utc
}

func firstValidString(values ...sql.NullString) *string {
	for _, value := range values {
		if value.Valid {
			return &value.String
		}
	}
	return nil
}

func severityRankForFindings(value string) int {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFORMATIONAL":
		return 1
	default:
		return 0
	}
}

func compareTimes(left time.Time, right time.Time) int {
	if left.Before(right) {
		return -1
	}
	if left.After(right) {
		return 1
	}
	return 0
}

func compareInts(left int, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareNullableInts(left *int, right *int, direction string) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return 1
	}
	if right == nil {
		return -1
	}
	if direction == "desc" {
		return compareInts(*right, *left)
	}
	return compareInts(*left, *right)
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
