package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const credentialManagePermission = "credential:manage"

type machineCredentialCreateRequest struct {
	Name string `json:"name"`
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
	response := machineCredentialListResponse{Credentials: make([]machineCredentialResponse, 0, len(credentials))}
	for _, credential := range credentials {
		response.Credentials = append(response.Credentials, machineCredentialResponseFromDB(credential))
	}
	writeJSON(w, http.StatusOK, response)
}

func createMachineCredential(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: credentialManagePermission}); !ok {
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
	writeJSON(w, http.StatusCreated, machineCredentialWithSecretResponse{
		machineCredentialResponse: machineCredentialResponseFromDB(credential),
		ClientSecret:              rawSecret,
	})
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

func machineCredentialResponseFromDB(credential dbgen.MachineCredential) machineCredentialResponse {
	var revokedAt *time.Time
	if credential.RevokedAt.Valid {
		value := credential.RevokedAt.Time.UTC()
		revokedAt = &value
	}
	return machineCredentialResponse{
		ID:        credential.ID,
		Name:      credential.Name,
		ClientID:  credential.ClientID,
		IsActive:  credential.IsActive,
		CreatedAt: credential.CreatedAt.UTC(),
		UpdatedAt: credential.UpdatedAt.UTC(),
		RevokedAt: revokedAt,
	}
}

func isUniqueConstraintError(err error) bool {
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "duplicate")
}
