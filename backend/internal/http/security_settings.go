package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

type securitySettingsResponse struct {
	ForcePeerReviewForStatusChanges bool `json:"force_peer_review_for_status_changes"`
	SessionIdleTimeoutMinutes       int  `json:"session_idle_timeout_minutes"`
	SessionAbsoluteTimeoutMinutes   int  `json:"session_absolute_timeout_minutes"`
}

func mountSecuritySettingsRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/admin/security-settings", func(w http.ResponseWriter, r *http.Request) {
		getSecuritySettings(w, r, settings, deps)
	})
	router.Patch("/api/admin/security-settings", func(w http.ResponseWriter, r *http.Request) {
		updateSecuritySettings(w, r, settings, deps)
	})
}

func getSecuritySettings(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "security_settings:manage"}); !ok {
		return
	}
	row, err := identity.GetOrCreateSecuritySettings(r.Context(), deps.DB, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, securitySettingsResponseFromDB(row, settings))
}

func updateSecuritySettings(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "security_settings:manage"})
	if !ok {
		return
	}
	var payload securitySettingsResponse
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid security settings request")
		return
	}
	if payload.SessionIdleTimeoutMinutes < 1 ||
		payload.SessionAbsoluteTimeoutMinutes < 1 ||
		payload.SessionAbsoluteTimeoutMinutes < payload.SessionIdleTimeoutMinutes {
		writeError(w, http.StatusUnprocessableEntity, "Invalid security settings request")
		return
	}
	row, err := identity.UpdateSecuritySettings(
		r.Context(),
		deps.DB,
		payload.ForcePeerReviewForStatusChanges,
		payload.SessionIdleTimeoutMinutes,
		payload.SessionAbsoluteTimeoutMinutes,
		time.Now().UTC(),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "security.settings.update",
		TargetType: stringPtr("app_security_settings"),
		TargetID:   stringPtr(row.ID),
		Metadata: map[string]any{
			"force_peer_review_for_status_changes": payload.ForcePeerReviewForStatusChanges,
			"session_idle_timeout_minutes":         payload.SessionIdleTimeoutMinutes,
			"session_absolute_timeout_minutes":     payload.SessionAbsoluteTimeoutMinutes,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, securitySettingsResponseFromDB(row, settings))
}

func securitySettingsResponseFromDB(row dbgen.AppSecuritySetting, settings config.Settings) securitySettingsResponse {
	idleTimeoutMinutes := settings.SessionIdleTimeoutMinutes
	if row.SessionIdleTimeoutMinutes.Valid {
		idleTimeoutMinutes = int(row.SessionIdleTimeoutMinutes.Int64)
	}
	absoluteTimeoutMinutes := settings.SessionAbsoluteTimeoutMinutes
	if row.SessionAbsoluteTimeoutMinutes.Valid {
		absoluteTimeoutMinutes = int(row.SessionAbsoluteTimeoutMinutes.Int64)
	}
	return securitySettingsResponse{
		ForcePeerReviewForStatusChanges: row.ForcePeerReviewForStatusChanges,
		SessionIdleTimeoutMinutes:       idleTimeoutMinutes,
		SessionAbsoluteTimeoutMinutes:   absoluteTimeoutMinutes,
	}
}
