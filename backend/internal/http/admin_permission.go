package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

type permissionTestRequest struct {
	PrincipalType string  `json:"principal_type"`
	PrincipalID   string  `json:"principal_id"`
	Permission    string  `json:"permission"`
	ScopeType     *string `json:"scope_type"`
	ScopeID       *string `json:"scope_id"`
}

type permissionTestResponse struct {
	Allowed     bool   `json:"allowed"`
	Explanation string `json:"explanation"`
}

func mountPermissionTestRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Post("/api/admin/permission-test", func(w http.ResponseWriter, r *http.Request) {
		testPermission(w, r, settings, deps)
	})
}

func testPermission(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "permission:test"}); !ok {
		return
	}

	var payload permissionTestRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid permission test request")
		return
	}

	result, err := identity.CheckPermission(r.Context(), deps.DB, identity.PermissionRequest{
		PrincipalType: payload.PrincipalType,
		PrincipalID:   payload.PrincipalID,
		Permission:    payload.Permission,
		ScopeType:     payload.ScopeType,
		ScopeID:       payload.ScopeID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid permission test request")
		return
	}

	writeJSON(w, http.StatusOK, permissionTestResponse{
		Allowed:     result.Allowed,
		Explanation: result.Explanation,
	})
}
