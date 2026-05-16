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
	before, err := identity.GetOrCreateSecuritySettings(r.Context(), deps.DB, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	oldResponse := securitySettingsResponseFromDB(before, settings)
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
	changes := securitySettingsChanges(oldResponse, payload)
	if len(changes) > 0 {
		if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
			Type:       "security.settings.update",
			TargetType: stringPtr("app_security_settings"),
			TargetID:   stringPtr(row.ID),
			Metadata: map[string]any{
				"changed_fields": securitySettingsChangedFields(changes),
				"changes":        changes,
			},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	writeJSON(w, http.StatusOK, securitySettingsResponseFromDB(row, settings))
}

func securitySettingsChanges(old securitySettingsResponse, next securitySettingsResponse) map[string]map[string]any {
	changes := map[string]map[string]any{}
	if old.ForcePeerReviewForStatusChanges != next.ForcePeerReviewForStatusChanges {
		changes["force_peer_review_for_status_changes"] = change(old.ForcePeerReviewForStatusChanges, next.ForcePeerReviewForStatusChanges)
	}
	if old.SessionIdleTimeoutMinutes != next.SessionIdleTimeoutMinutes {
		changes["session_idle_timeout_minutes"] = change(old.SessionIdleTimeoutMinutes, next.SessionIdleTimeoutMinutes)
	}
	if old.SessionAbsoluteTimeoutMinutes != next.SessionAbsoluteTimeoutMinutes {
		changes["session_absolute_timeout_minutes"] = change(old.SessionAbsoluteTimeoutMinutes, next.SessionAbsoluteTimeoutMinutes)
	}
	return changes
}

func securitySettingsChangedFields(changes map[string]map[string]any) []string {
	fields := []string{}
	for _, field := range []string{
		"force_peer_review_for_status_changes",
		"session_idle_timeout_minutes",
		"session_absolute_timeout_minutes",
	} {
		if _, ok := changes[field]; ok {
			fields = append(fields, field)
		}
	}
	return fields
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
