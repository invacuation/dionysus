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
	"github.com/google/uuid"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
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
	PeerReviewRequired   bool                                 `json:"peer_review_required_for_status_changes"`
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

type findingCommentCreateRequest struct {
	Body string `json:"body"`
}

type findingStatusUpdateRequest struct {
	Status            string `json:"status"`
	Comment           string `json:"comment"`
	RequirePeerReview bool   `json:"require_peer_review"`
}

type findingStatusApprovalRequest struct {
	Comment *string `json:"comment"`
}

type findingStatusRejectionRequest struct {
	Comment string `json:"comment"`
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
	router.Post("/api/findings/{findingID}/comments", func(w http.ResponseWriter, r *http.Request) {
		createFindingComment(w, r, settings, deps)
	})
	router.Post("/api/findings/{findingID}/status", func(w http.ResponseWriter, r *http.Request) {
		updateFindingStatus(w, r, settings, deps)
	})
	router.Post("/api/findings/{findingID}/status-requests/{requestID}/approve", func(w http.ResponseWriter, r *http.Request) {
		reviewFindingStatusRequest(w, r, settings, deps, true)
	})
	router.Post("/api/findings/{findingID}/status-requests/{requestID}/reject", func(w http.ResponseWriter, r *http.Request) {
		reviewFindingStatusRequest(w, r, settings, deps, false)
	})
	router.Post("/api/findings/{findingID}/status-requests/{requestID}/retract", func(w http.ResponseWriter, r *http.Request) {
		retractFindingStatusRequest(w, r, settings, deps)
	})
	router.Patch("/api/findings/{findingID}/status-requests/{requestID}/retract", func(w http.ResponseWriter, r *http.Request) {
		retractFindingStatusRequest(w, r, settings, deps)
	})
	router.Delete("/api/findings/{findingID}/status-requests/{requestID}/retract", func(w http.ResponseWriter, r *http.Request) {
		retractFindingStatusRequest(w, r, settings, deps)
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

func createFindingComment(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	findingID := chi.URLParam(r, "findingID")
	queries := dbgen.New(deps.DB)
	row, ok := requireFindingRow(w, r, queries, findingID)
	if !ok {
		return
	}
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "finding:comment", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)})
	if !ok {
		return
	}
	var payload findingCommentCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid comment request")
		return
	}
	body := strings.TrimSpace(payload.Body)
	if body == "" {
		writeError(w, http.StatusBadRequest, "Comment body is required")
		return
	}
	now := time.Now().UTC()
	comment, err := queries.CreateFindingComment(r.Context(), dbgen.CreateFindingCommentParams{
		ID:                  uuid.NewString(),
		FindingID:           row.FindingID,
		ProjectID:           row.ProjectID,
		AuthorPrincipalType: actor.PrincipalType,
		AuthorPrincipalID:   actor.PrincipalID,
		Body:                body,
		IsSystem:            false,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "finding.comment.created",
		TargetType: stringPtr("finding"),
		TargetID:   stringPtr(row.FindingID),
		ProjectID:  stringPtr(row.ProjectID),
		Metadata:   map[string]any{"comment_id": comment.ID},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, findingCommentResponseFromDB(comment, actor.DisplayName))
}

func updateFindingStatus(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	findingID := chi.URLParam(r, "findingID")
	queries := dbgen.New(deps.DB)
	row, ok := requireFindingRow(w, r, queries, findingID)
	if !ok {
		return
	}
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "finding:status_change:request", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)})
	if !ok {
		return
	}
	var payload findingStatusUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid status request")
		return
	}
	targetStatus := strings.TrimSpace(payload.Status)
	if !findingStatuses[targetStatus] {
		writeError(w, http.StatusBadRequest, "Unsupported finding status")
		return
	}
	commentBody := strings.TrimSpace(payload.Comment)
	if targetStatus != row.Status && targetStatus != "open" && commentBody == "" {
		writeError(w, http.StatusBadRequest, "Status change comment is required")
		return
	}
	requireReview, err := effectivePeerReviewRequired(r, queries, row.ProjectID, payload.RequirePeerReview)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	now := time.Now().UTC()
	state := "approved"
	decidedAt := sql.NullTime{Time: now, Valid: true}
	if requireReview {
		state = "pending"
		decidedAt = sql.NullTime{}
	}
	request, comment, err := createFindingStatusActivity(r, queries, row, *actor, targetStatus, commentBody, state, decidedAt, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !requireReview {
		if err := applyFindingStatus(r, queries, row, targetStatus, now); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if _, err := recordReleaseStatusDecision(r, queries, row, targetStatus, &comment.ID, &request.ID, now); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	eventType := "finding.status.changed"
	if requireReview {
		eventType = "finding.status.requested"
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       eventType,
		TargetType: stringPtr("finding"),
		TargetID:   stringPtr(row.FindingID),
		ProjectID:  stringPtr(row.ProjectID),
		Metadata: map[string]any{
			"request_id":  request.ID,
			"comment_id":  comment.ID,
			"from_status": row.Status,
			"to_status":   targetStatus,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeUpdatedFindingDetail(w, r, queries, row.FindingID)
}

func reviewFindingStatusRequest(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies, approve bool) {
	findingID := chi.URLParam(r, "findingID")
	requestID := chi.URLParam(r, "requestID")
	queries := dbgen.New(deps.DB)
	row, ok := requireFindingRow(w, r, queries, findingID)
	if !ok {
		return
	}
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "finding:status_change:approve", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)})
	if !ok {
		return
	}
	statusRequest, err := queries.GetFindingStatusChangeRequest(r.Context(), dbgen.GetFindingStatusChangeRequestParams{ID: requestID, FindingID: findingID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Status change request not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if statusRequest.State != "pending" {
		writeError(w, http.StatusBadRequest, "Status change request is not pending")
		return
	}
	if statusRequest.RequesterPrincipalType == actor.PrincipalType && statusRequest.RequesterPrincipalID == actor.PrincipalID {
		writeError(w, http.StatusBadRequest, "Requester cannot review their own status change")
		return
	}
	decisionComment, ok := decodeFindingReviewComment(w, r, approve)
	if !ok {
		return
	}
	now := time.Now().UTC()
	state := "approved"
	eventType := "finding.status.approved"
	if !approve {
		state = "rejected"
		eventType = "finding.status.rejected"
	}
	updatedRequest, err := queries.UpdateFindingStatusChangeRequestDecision(r.Context(), dbgen.UpdateFindingStatusChangeRequestDecisionParams{
		State:                 state,
		ReviewerPrincipalType: sql.NullString{String: actor.PrincipalType, Valid: true},
		ReviewerPrincipalID:   sql.NullString{String: actor.PrincipalID, Valid: true},
		DecisionComment:       nullStringFromPtr(decisionComment),
		DecidedAt:             sql.NullTime{Time: now, Valid: true},
		UpdatedAt:             now,
		ID:                    requestID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if approve {
		if err := applyFindingStatus(r, queries, row, statusRequest.ToStatus, now); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if _, err := recordReleaseStatusDecision(r, queries, row, statusRequest.ToStatus, nil, &updatedRequest.ID, now); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       eventType,
		TargetType: stringPtr("finding"),
		TargetID:   stringPtr(row.FindingID),
		ProjectID:  stringPtr(row.ProjectID),
		Metadata: map[string]any{
			"request_id":  requestID,
			"from_status": statusRequest.FromStatus,
			"to_status":   statusRequest.ToStatus,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeUpdatedFindingDetail(w, r, queries, row.FindingID)
}

func retractFindingStatusRequest(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	findingID := chi.URLParam(r, "findingID")
	requestID := chi.URLParam(r, "requestID")
	queries := dbgen.New(deps.DB)
	row, ok := requireFindingRow(w, r, queries, findingID)
	if !ok {
		return
	}
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "finding:status_change:request", ScopeType: stringPtr("project"), ScopeID: stringPtr(row.ProjectID)})
	if !ok {
		return
	}
	statusRequest, err := queries.GetFindingStatusChangeRequest(r.Context(), dbgen.GetFindingStatusChangeRequestParams{ID: requestID, FindingID: findingID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Status change request not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if statusRequest.State != "pending" {
		writeError(w, http.StatusBadRequest, "Status change request is not pending")
		return
	}
	if statusRequest.RequesterPrincipalType != actor.PrincipalType || statusRequest.RequesterPrincipalID != actor.PrincipalID {
		writeError(w, http.StatusBadRequest, "Only the requester can retract this status change")
		return
	}
	now := time.Now().UTC()
	if _, err := queries.UpdateFindingStatusChangeRequestDecision(r.Context(), dbgen.UpdateFindingStatusChangeRequestDecisionParams{
		State:                 "retracted",
		ReviewerPrincipalType: sql.NullString{},
		ReviewerPrincipalID:   sql.NullString{},
		DecisionComment:       sql.NullString{},
		DecidedAt:             sql.NullTime{Time: now, Valid: true},
		UpdatedAt:             now,
		ID:                    requestID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "finding.status.retracted",
		TargetType: stringPtr("finding"),
		TargetID:   stringPtr(row.FindingID),
		ProjectID:  stringPtr(row.ProjectID),
		Metadata: map[string]any{
			"request_id":  requestID,
			"from_status": statusRequest.FromStatus,
			"to_status":   statusRequest.ToStatus,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeUpdatedFindingDetail(w, r, queries, row.FindingID)
}

func requireFindingRow(w http.ResponseWriter, r *http.Request, queries *dbgen.Queries, findingID string) (dbgen.GetFindingRowRow, bool) {
	row, err := queries.GetFindingRow(r.Context(), findingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Finding not found")
			return dbgen.GetFindingRowRow{}, false
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return dbgen.GetFindingRowRow{}, false
	}
	return row, true
}

func writeUpdatedFindingDetail(w http.ResponseWriter, r *http.Request, queries *dbgen.Queries, findingID string) {
	updatedRow, err := queries.GetFindingRow(r.Context(), findingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Finding not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response, err := findingDetailResponseFromDB(r, queries, updatedRow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func findingCommentResponseFromDB(comment dbgen.FindingComment, authorDisplay string) findingCommentResponse {
	display := stringPtr(authorDisplay)
	if strings.TrimSpace(authorDisplay) == "" {
		display = nil
	}
	return findingCommentResponse{
		ID:                  comment.ID,
		Body:                comment.Body,
		AuthorPrincipalType: comment.AuthorPrincipalType,
		AuthorPrincipalID:   comment.AuthorPrincipalID,
		AuthorDisplay:       display,
		CreatedAt:           comment.CreatedAt.UTC(),
		IsSystem:            comment.IsSystem,
		StatusFrom:          optionalStringFromNull(comment.StatusFrom),
		StatusTo:            optionalStringFromNull(comment.StatusTo),
	}
}

func createFindingStatusActivity(
	r *http.Request,
	queries *dbgen.Queries,
	row dbgen.GetFindingRowRow,
	actor identity.AuthenticatedActor,
	targetStatus string,
	commentBody string,
	state string,
	decidedAt sql.NullTime,
	now time.Time,
) (dbgen.FindingStatusChangeRequest, dbgen.FindingComment, error) {
	request, err := queries.CreateFindingStatusChangeRequest(r.Context(), dbgen.CreateFindingStatusChangeRequestParams{
		ID:                     uuid.NewString(),
		FindingID:              row.FindingID,
		ProjectID:              row.ProjectID,
		RequesterPrincipalType: actor.PrincipalType,
		RequesterPrincipalID:   actor.PrincipalID,
		FromStatus:             row.Status,
		ToStatus:               targetStatus,
		State:                  state,
		Comment:                nullStringFromPtr(stringPtrOrNil(commentBody)),
		DecidedAt:              decidedAt,
		CreatedAt:              now,
		UpdatedAt:              now,
	})
	if err != nil {
		return dbgen.FindingStatusChangeRequest{}, dbgen.FindingComment{}, err
	}
	comment, err := queries.CreateFindingComment(r.Context(), dbgen.CreateFindingCommentParams{
		ID:                  uuid.NewString(),
		FindingID:           row.FindingID,
		ProjectID:           row.ProjectID,
		AuthorPrincipalType: actor.PrincipalType,
		AuthorPrincipalID:   actor.PrincipalID,
		Body:                commentBody,
		IsSystem:            false,
		StatusFrom:          sql.NullString{String: row.Status, Valid: true},
		StatusTo:            sql.NullString{String: targetStatus, Valid: true},
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	return request, comment, err
}

func applyFindingStatus(r *http.Request, queries *dbgen.Queries, row dbgen.GetFindingRowRow, status string, now time.Time) error {
	if _, err := queries.UpdateRawFindingStatus(r.Context(), dbgen.UpdateRawFindingStatusParams{Status: status, UpdatedAt: now, ID: row.FindingID}); err != nil {
		return err
	}
	return queries.UpdateProjectVulnerabilityGroupStatus(r.Context(), dbgen.UpdateProjectVulnerabilityGroupStatusParams{
		Status:    status,
		UpdatedAt: now,
		ProjectID: row.ProjectID,
		DedupeKey: row.PrimaryIdentifier,
	})
}

func effectivePeerReviewRequired(r *http.Request, queries *dbgen.Queries, projectID string, requested bool) (bool, error) {
	if requested {
		return true, nil
	}
	appSettings, err := queries.GetAppSecuritySettings(r.Context(), identity.AppSecuritySettingsID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil && appSettings.ForcePeerReviewForStatusChanges {
		return true, nil
	}
	project, err := queries.GetProject(r.Context(), projectID)
	if err != nil {
		return false, err
	}
	return project.RequirePeerReviewForStatusChanges, nil
}

func decodeFindingReviewComment(w http.ResponseWriter, r *http.Request, approve bool) (*string, bool) {
	if approve {
		var payload findingStatusApprovalRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "Invalid review request")
			return nil, false
		}
		if payload.Comment == nil {
			return nil, true
		}
		trimmed := strings.TrimSpace(*payload.Comment)
		if trimmed == "" {
			return nil, true
		}
		return &trimmed, true
	}
	var payload findingStatusRejectionRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid review request")
		return nil, false
	}
	trimmed := strings.TrimSpace(payload.Comment)
	if trimmed == "" {
		writeError(w, http.StatusBadRequest, "Decision comment is required")
		return nil, false
	}
	return &trimmed, true
}

type releaseContext struct {
	ScopeAssetID   string
	ScopePath      string
	VersionAssetID string
	VersionPath    string
	Version        string
}

func releaseContextForScanTarget(r *http.Request, queries *dbgen.Queries, scanTargetID string) (*releaseContext, error) {
	target, err := queries.GetAssetNode(r.Context(), scanTargetID)
	if err != nil {
		return nil, err
	}
	assets, err := queries.ListProjectAssets(r.Context(), target.ProjectID)
	if err != nil {
		return nil, err
	}
	byID := map[string]dbgen.AssetNode{}
	for _, asset := range assets {
		byID[asset.ID] = asset
	}
	pathFromTarget := []dbgen.AssetNode{}
	current := target
	for {
		if current.ProjectID != target.ProjectID {
			return nil, nil
		}
		if _, ok := metadataObject(current.MetadataJson); !ok {
			return nil, nil
		}
		pathFromTarget = append(pathFromTarget, current)
		if !current.ParentID.Valid {
			break
		}
		parent, ok := byID[current.ParentID.String]
		if !ok {
			return nil, nil
		}
		current = parent
	}
	path := make([]dbgen.AssetNode, 0, len(pathFromTarget))
	for index := len(pathFromTarget) - 1; index >= 0; index-- {
		path = append(path, pathFromTarget[index])
	}
	for index := len(path) - 2; index >= 0; index-- {
		ancestor := path[index]
		if ancestor.NodeType != "folder" {
			continue
		}
		metadata, ok := metadataObject(ancestor.MetadataJson)
		if !ok {
			return nil, nil
		}
		if metadata["release_inheritance_scope"] != true {
			continue
		}
		versionAsset := path[index+1]
		if versionAsset.NodeType != "folder" {
			return nil, nil
		}
		versionMetadata, ok := metadataObject(versionAsset.MetadataJson)
		if !ok {
			return nil, nil
		}
		version := ""
		if raw, exists := versionMetadata["release_version"]; exists {
			version = strings.TrimSpace(stringFromAny(raw))
		}
		if version == "" {
			version = strings.TrimSpace(versionAsset.Name)
		}
		if version == "" {
			return nil, nil
		}
		return &releaseContext{
			ScopeAssetID:   ancestor.ID,
			ScopePath:      ancestor.Path,
			VersionAssetID: versionAsset.ID,
			VersionPath:    versionAsset.Path,
			Version:        version,
		}, nil
	}
	return nil, nil
}

func recordReleaseStatusDecision(r *http.Request, queries *dbgen.Queries, row dbgen.GetFindingRowRow, status string, commentID *string, requestID *string, decidedAt time.Time) (*dbgen.FindingReleaseStatusDecision, error) {
	context, err := releaseContextForScanTarget(r, queries, row.ScanTargetID)
	if err != nil || context == nil {
		return nil, err
	}
	now := time.Now().UTC()
	decision, err := queries.UpsertFindingReleaseStatusDecision(r.Context(), dbgen.UpsertFindingReleaseStatusDecisionParams{
		ID:                    uuid.NewString(),
		ProjectID:             row.ProjectID,
		ReleaseScopeAssetID:   context.ScopeAssetID,
		ReleaseVersionAssetID: context.VersionAssetID,
		ReleaseVersion:        context.Version,
		ScannerKind:           row.ScannerKind,
		ReportKind:            row.ReportKind,
		FindingIdentity:       findingInheritanceIdentity(row.PrimaryIdentifier, optionalStringValue(row.PackageName)),
		Status:                status,
		SourceFindingID:       row.FindingID,
		SourceCommentID:       nullStringFromPtr(commentID),
		SourceRequestID:       nullStringFromPtr(requestID),
		DecidedAt:             decidedAt,
		CreatedAt:             now,
		UpdatedAt:             now,
	})
	if err != nil {
		return nil, err
	}
	return &decision, nil
}

func latestApplicableReleaseDecision(r *http.Request, queries *dbgen.Queries, projectID string, scanTargetID string, scannerKind string, reportKind string, primaryIdentifier string, packageName string) (*dbgen.FindingReleaseStatusDecision, *releaseContext, error) {
	context, err := releaseContextForScanTarget(r, queries, scanTargetID)
	if err != nil || context == nil {
		return nil, context, err
	}
	decisions, err := queries.ListReleaseStatusDecisions(r.Context(), dbgen.ListReleaseStatusDecisionsParams{
		ProjectID:           projectID,
		ReleaseScopeAssetID: context.ScopeAssetID,
		ScannerKind:         scannerKind,
		ReportKind:          reportKind,
		FindingIdentity:     findingInheritanceIdentity(primaryIdentifier, packageName),
	})
	if err != nil {
		return nil, context, err
	}
	return chooseLatestReleaseDecision(decisions, context.Version), context, nil
}

func chooseLatestReleaseDecision(decisions []dbgen.FindingReleaseStatusDecision, targetVersion string) *dbgen.FindingReleaseStatusDecision {
	targetNumeric, targetOK := parseNumericVersion(targetVersion)
	maxLen := len(targetNumeric)
	decisionVersions := make([][]int, len(decisions))
	for index, decision := range decisions {
		parsed, ok := parseNumericVersion(decision.ReleaseVersion)
		if ok {
			decisionVersions[index] = parsed
			if len(parsed) > maxLen {
				maxLen = len(parsed)
			}
		}
	}
	var best *dbgen.FindingReleaseStatusDecision
	var bestVersion []int
	for index := range decisions {
		decision := decisions[index]
		parsed := decisionVersions[index]
		if targetOK && parsed != nil {
			paddedDecision := padVersion(parsed, maxLen)
			if compareVersion(paddedDecision, padVersion(targetNumeric, maxLen)) > 0 {
				continue
			}
			if best == nil || compareVersion(paddedDecision, bestVersion) > 0 || (compareVersion(paddedDecision, bestVersion) == 0 && releaseDecisionTieBreak(decision, *best) > 0) {
				copyDecision := decision
				best = &copyDecision
				bestVersion = paddedDecision
			}
			continue
		}
		if !targetOK && decision.ReleaseVersion == targetVersion {
			if best == nil || releaseDecisionTieBreak(decision, *best) > 0 {
				copyDecision := decision
				best = &copyDecision
				bestVersion = []int{}
			}
		}
	}
	return best
}

func releaseDecisionTieBreak(left dbgen.FindingReleaseStatusDecision, right dbgen.FindingReleaseStatusDecision) int {
	if cmp := compareTimes(left.DecidedAt, right.DecidedAt); cmp != 0 {
		return cmp
	}
	if cmp := compareTimes(left.CreatedAt, right.CreatedAt); cmp != 0 {
		return cmp
	}
	return strings.Compare(left.ID, right.ID)
}

func metadataObject(raw string) (map[string]any, bool) {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}, true
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, false
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	return metadata, true
}

func findingInheritanceIdentity(primaryIdentifier string, packageName string) string {
	return strings.TrimSpace(primaryIdentifier) + "|" + strings.TrimSpace(packageName)
}

func parseNumericVersion(version string) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) == 0 {
		return nil, false
	}
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		value := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				return nil, false
			}
			value = value*10 + int(char-'0')
		}
		values = append(values, value)
	}
	return values, true
}

func padVersion(version []int, length int) []int {
	padded := make([]int, length)
	copy(padded, version)
	return padded
}

func compareVersion(left []int, right []int) int {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return compareInts(len(left), len(right))
}

func stringFromAny(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
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
	peerReviewRequired, err := effectivePeerReviewRequired(r, queries, row.ProjectID, false)
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
		PeerReviewRequired:   peerReviewRequired,
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
		ReportKind:                     row.ReportKind,
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
