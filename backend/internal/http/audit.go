package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const maxAuditLimit = 200

type auditLogResponse struct {
	EventTypes []string                `json:"event_types"`
	Events     []auditLogEventResponse `json:"events"`
}

type auditLogEventResponse struct {
	ID                 string         `json:"id"`
	EventType          string         `json:"event_type"`
	ActorPrincipalType *string        `json:"actor_principal_type"`
	ActorPrincipalID   *string        `json:"actor_principal_id"`
	ActorDisplay       *string        `json:"actor_display"`
	TargetType         *string        `json:"target_type"`
	TargetID           *string        `json:"target_id"`
	ProjectID          *string        `json:"project_id"`
	IPAddress          *string        `json:"ip_address"`
	UserAgent          *string        `json:"user_agent"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          time.Time      `json:"created_at"`
}

func mountAuditRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/audit-log", func(w http.ResponseWriter, r *http.Request) {
		listAuditLog(w, r, settings, deps)
	})
}

// Retrieve the current audit log (with optional filtering for project, event type, timerange).
// Users must have the "audit_log:view" permission to access this endpoint.
func listAuditLog(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "audit_log:view"}); !ok {
		return
	}

	createdFrom, ok := parseAuditTimeParam(w, r, "created_from")
	if !ok {
		return
	}
	createdTo, ok := parseAuditTimeParam(w, r, "created_to")
	if !ok {
		return
	}
	if createdFrom != nil && createdTo != nil && createdFrom.After(*createdTo) {
		writeError(w, http.StatusBadRequest, "created_from must be at or before created_to.")
		return
	}

	queries := dbgen.New(deps.DB)
	eventTypes, err := queries.ListAuditEventTypes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	rows, err := queries.ListAuditLogEvents(r.Context(), auditLogQueryParams(r, createdFrom, createdTo))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	events := make([]auditLogEventResponse, 0, len(rows))
	for _, row := range rows {
		event, err := auditLogEventResponseFromDB(row)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		events = append(events, event)
	}
	writeJSON(w, http.StatusOK, auditLogResponse{EventTypes: eventTypes, Events: events})
}

func auditLogQueryParams(r *http.Request, createdFrom *time.Time, createdTo *time.Time) dbgen.ListAuditLogEventsParams {
	query := r.URL.Query()
	eventType := query.Get("event_type")
	projectID := query.Get("project_id")
	targetType := query.Get("target_type")
	targetID := query.Get("target_id")
	limit := int64(50)
	if rawLimit := query.Get("limit"); rawLimit != "" {
		if parsed, err := strconv.ParseInt(rawLimit, 10, 64); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	params := dbgen.ListAuditLogEventsParams{
		Column1:     nil,
		EventType:   eventType,
		Column3:     nil,
		ProjectID:   nullStringFromValue(projectID),
		Column5:     nil,
		TargetType:  nullStringFromValue(targetType),
		Column7:     nil,
		TargetID:    nullStringFromValue(targetID),
		Column9:     nil,
		CreatedAt:   time.Time{},
		Column11:    nil,
		CreatedAt_2: time.Time{},
		Limit:       limit,
	}
	if eventType != "" {
		params.Column1 = eventType
	}
	if projectID != "" {
		params.Column3 = projectID
	}
	if targetType != "" {
		params.Column5 = targetType
	}
	if targetID != "" {
		params.Column7 = targetID
	}
	if createdFrom != nil {
		params.Column9 = *createdFrom
		params.CreatedAt = *createdFrom
	}
	if createdTo != nil {
		params.Column11 = *createdTo
		params.CreatedAt_2 = *createdTo
	}
	return params
}

func parseAuditTimeParam(w http.ResponseWriter, r *http.Request, name string) (*time.Time, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, true
	}
	parsed, err := parseISOTime(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, name+" must be a valid ISO datetime.")
		return nil, false
	}
	return &parsed, true
}

func parseISOTime(raw string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := time.Parse("2006-01-02T15:04:05", raw); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, http.ErrNotSupported
}

func auditLogEventResponseFromDB(row dbgen.AuditLogEvent) (auditLogEventResponse, error) {
	metadata := map[string]any{}
	if err := json.Unmarshal([]byte(row.MetadataJson), &metadata); err != nil {
		return auditLogEventResponse{}, err
	}
	enrichMetadata(metadata, "actor_principal_id", row.ActorPrincipalID)
	enrichMetadata(metadata, "target_id", row.TargetID)
	enrichMetadata(metadata, "project_id", row.ProjectID)
	return auditLogEventResponse{
		ID:                 row.ID,
		EventType:          row.EventType,
		ActorPrincipalType: optionalStringFromNull(row.ActorPrincipalType),
		ActorPrincipalID:   optionalStringFromNull(row.ActorPrincipalID),
		ActorDisplay:       optionalStringFromNull(row.ActorDisplay),
		TargetType:         optionalStringFromNull(row.TargetType),
		TargetID:           optionalStringFromNull(row.TargetID),
		ProjectID:          optionalStringFromNull(row.ProjectID),
		IPAddress:          optionalStringFromNull(row.IpAddress),
		UserAgent:          optionalStringFromNull(row.UserAgent),
		Metadata:           metadata,
		CreatedAt:          row.CreatedAt.UTC(),
	}, nil
}

func enrichMetadata(metadata map[string]any, key string, value sql.NullString) {
	if !value.Valid {
		return
	}
	if _, exists := metadata[key]; !exists {
		metadata[key] = value.String
	}
}

func nullStringFromValue(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
