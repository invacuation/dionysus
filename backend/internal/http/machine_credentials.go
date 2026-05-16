package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const credentialManagePermission = "credential:manage"

type machineCredentialCreateRequest struct {
	Name string `json:"name"`
}

func optionalStringFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func nullStringFromPtr(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

type machineCredentialTokenActionRequest struct {
	RevokeTokens *bool `json:"revoke_tokens"`
}

type machineCredentialResponse struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	ClientID               string     `json:"client_id"`
	IsActive               bool       `json:"is_active"`
	CreatedByPrincipalType *string    `json:"created_by_principal_type"`
	CreatedByPrincipalID   *string    `json:"created_by_principal_id"`
	CreatedByDisplay       *string    `json:"created_by_display"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

type machineCredentialWithSecretResponse struct {
	machineCredentialResponse
	ClientSecret string `json:"client_secret"`
}

type machineCredentialListResponse struct {
	Credentials []machineCredentialResponse `json:"credentials"`
}

func mountMachineCredentialRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/admin/machine-credentials", func(w http.ResponseWriter, r *http.Request) {
		listMachineCredentials(w, r, settings, deps)
	})
	router.Post("/api/admin/machine-credentials", func(w http.ResponseWriter, r *http.Request) {
		createMachineCredential(w, r, settings, deps)
	})
	router.Post("/api/admin/machine-credentials/{credentialID}/regenerate-secret", func(w http.ResponseWriter, r *http.Request) {
		regenerateMachineCredentialSecret(w, r, settings, deps)
	})
	router.Post("/api/admin/machine-credentials/{credentialID}/revoke", func(w http.ResponseWriter, r *http.Request) {
		revokeMachineCredential(w, r, settings, deps)
	})
}

func listMachineCredentials(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: credentialManagePermission}); !ok {
		return
	}
	credentials, err := dbgen.New(deps.DB).ListMachineCredentials(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	creatorEvents, err := machineCredentialCreatorEvents(r, dbgen.New(deps.DB))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response := machineCredentialListResponse{Credentials: make([]machineCredentialResponse, 0, len(credentials))}
	for _, credential := range credentials {
		response.Credentials = append(response.Credentials, machineCredentialResponseFromDB(credential, creatorEvents[credential.ID]))
	}
	writeJSON(w, http.StatusOK, response)
}

func createMachineCredential(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: credentialManagePermission})
	if !ok {
		return
	}
	var payload machineCredentialCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid machine credential request")
		return
	}
	rawSecret, credential, err := identity.CreateMachineCredential(r.Context(), deps.DB, payload.Name, time.Now().UTC())
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Machine credential name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "machine_credential.create",
		TargetType: stringPtr("machine_credential"),
		TargetID:   stringPtr(credential.ID),
		Metadata:   map[string]any{"name": credential.Name},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, machineCredentialWithSecretResponse{
		machineCredentialResponse: machineCredentialResponseFromDB(credential, nil),
		ClientSecret:              rawSecret,
	})
}

func regenerateMachineCredentialSecret(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: credentialManagePermission})
	if !ok {
		return
	}
	revokeTokens, ok := tokenActionRevokeTokens(w, r)
	if !ok {
		return
	}
	rawSecret, credential, err := identity.RegenerateMachineClientSecret(
		r.Context(),
		deps.DB,
		chi.URLParam(r, "credentialID"),
		time.Now().UTC(),
		revokeTokens,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Machine credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "machine_credential.regenerate_secret",
		TargetType: stringPtr("machine_credential"),
		TargetID:   stringPtr(credential.ID),
		Metadata: map[string]any{
			"name":          credential.Name,
			"revoke_tokens": revokeTokens,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, machineCredentialWithSecretResponse{
		machineCredentialResponse: machineCredentialResponseFromDB(credential, nil),
		ClientSecret:              rawSecret,
	})
}

func revokeMachineCredential(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: credentialManagePermission})
	if !ok {
		return
	}
	revokeTokens, ok := tokenActionRevokeTokens(w, r)
	if !ok {
		return
	}
	credential, err := identity.RevokeMachineCredential(
		r.Context(),
		deps.DB,
		chi.URLParam(r, "credentialID"),
		time.Now().UTC(),
		revokeTokens,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "Machine credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "machine_credential.revoke",
		TargetType: stringPtr("machine_credential"),
		TargetID:   stringPtr(credential.ID),
		Metadata: map[string]any{
			"name":          credential.Name,
			"revoke_tokens": revokeTokens,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, machineCredentialResponseFromDB(credential, nil))
}

func tokenActionRevokeTokens(w http.ResponseWriter, r *http.Request) (bool, bool) {
	if r.Body == nil {
		return true, true
	}
	payload := machineCredentialTokenActionRequest{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		if errors.Is(err, http.ErrBodyReadAfterClose) {
			return true, true
		}
		writeError(w, http.StatusUnprocessableEntity, "Invalid machine credential request")
		return false, false
	}
	if payload.RevokeTokens == nil {
		return true, true
	}
	return *payload.RevokeTokens, true
}

func requireActorPermission(
	w http.ResponseWriter,
	r *http.Request,
	settings config.Settings,
	deps Dependencies,
	request identity.PermissionRequest,
) (*identity.AuthenticatedActor, bool) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return nil, false
	}
	actor, ok := authenticatedActorFromRequest(w, r, settings, deps)
	if !ok {
		return nil, false
	}
	_, err := identity.EnsureActorPermission(r.Context(), deps.DB, *actor, request)
	if err != nil {
		if errors.Is(err, identity.ErrForbidden) {
			writeError(w, http.StatusForbidden, "Forbidden")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return actor, true
}

func machineCredentialCreatorEvents(r *http.Request, queries *dbgen.Queries) (map[string]*dbgen.AuditLogEvent, error) {
	rows, err := queries.ListAuditLogEvents(r.Context(), dbgen.ListAuditLogEventsParams{
		Column1:     "machine_credential.create",
		EventType:   "machine_credential.create",
		Column3:     nil,
		ProjectID:   sql.NullString{},
		Column5:     nil,
		TargetType:  sql.NullString{},
		Column7:     nil,
		TargetID:    sql.NullString{},
		Column9:     nil,
		CreatedAt:   time.Time{},
		Column11:    nil,
		CreatedAt_2: time.Time{},
		Limit:       200,
	})
	if err != nil {
		return nil, err
	}
	creators := map[string]*dbgen.AuditLogEvent{}
	for i := range rows {
		if !rows[i].TargetID.Valid {
			continue
		}
		if _, exists := creators[rows[i].TargetID.String]; !exists {
			creators[rows[i].TargetID.String] = &rows[i]
		}
	}
	return creators, nil
}

func machineCredentialResponseFromDB(credential dbgen.MachineCredential, creatorEvent *dbgen.AuditLogEvent) machineCredentialResponse {
	var revokedAt *time.Time
	if credential.RevokedAt.Valid {
		value := credential.RevokedAt.Time.UTC()
		revokedAt = &value
	}
	var createdByPrincipalType *string
	var createdByPrincipalID *string
	var createdByDisplay *string
	if creatorEvent != nil {
		createdByPrincipalType = optionalStringFromNull(creatorEvent.ActorPrincipalType)
		createdByPrincipalID = optionalStringFromNull(creatorEvent.ActorPrincipalID)
		createdByDisplay = optionalStringFromNull(creatorEvent.ActorDisplay)
	}
	return machineCredentialResponse{
		ID:                     credential.ID,
		Name:                   credential.Name,
		ClientID:               credential.ClientID,
		IsActive:               credential.IsActive,
		CreatedByPrincipalType: createdByPrincipalType,
		CreatedByPrincipalID:   createdByPrincipalID,
		CreatedByDisplay:       createdByDisplay,
		CreatedAt:              credential.CreatedAt.UTC(),
		UpdatedAt:              credential.UpdatedAt.UTC(),
		RevokedAt:              revokedAt,
	}
}

func isUniqueConstraintError(err error) bool {
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "duplicate")
}
