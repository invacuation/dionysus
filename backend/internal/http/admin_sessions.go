package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

type adminSessionListResponse struct {
	Sessions []adminSessionResponse `json:"sessions"`
}

type adminSessionResponse struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Username      string     `json:"username"`
	DisplayName   string     `json:"display_name"`
	IPAddress     *string    `json:"ip_address"`
	UserAgent     *string    `json:"user_agent"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	IdleExpiresAt time.Time  `json:"idle_expires_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	Active        bool       `json:"active"`
}

func mountAdminSessionRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/admin/sessions", func(w http.ResponseWriter, r *http.Request) {
		listAdminSessions(w, r, settings, deps)
	})
	router.Post("/api/admin/sessions/{sessionID}/revoke", func(w http.ResponseWriter, r *http.Request) {
		revokeAdminSession(w, r, settings, deps)
	})
}

func listAdminSessions(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "session:manage"}); !ok {
		return
	}
	rows, err := dbgen.New(deps.DB).ListUserSessionsWithUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	now := time.Now().UTC()
	sessions := make([]adminSessionResponse, 0, len(rows))
	for _, row := range rows {
		sessions = append(sessions, adminSessionResponseFromRow(row, now))
	}
	writeJSON(w, http.StatusOK, adminSessionListResponse{Sessions: sessions})
}

func revokeAdminSession(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "session:manage"}); !ok {
		return
	}
	sessionID := chi.URLParam(r, "sessionID")
	queries := dbgen.New(deps.DB)
	now := time.Now().UTC()
	if _, err := queries.RevokeUserSession(r.Context(), dbgen.RevokeUserSessionParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UpdatedAt: now,
		ID:        sessionID,
	}); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	row, err := queries.GetUserSessionWithUser(r.Context(), sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, adminSessionResponseFromGetRow(row, now))
}

func adminSessionResponseFromRow(row dbgen.ListUserSessionsWithUsersRow, now time.Time) adminSessionResponse {
	revokedAt := timePtrFromNull(row.RevokedAt)
	return adminSessionResponse{
		ID:            row.ID,
		UserID:        row.UserID,
		Username:      row.Username,
		DisplayName:   row.DisplayName,
		IPAddress:     optionalStringFromNull(row.IpAddress),
		UserAgent:     optionalStringFromNull(row.UserAgent),
		CreatedAt:     row.CreatedAt.UTC(),
		LastSeenAt:    row.LastSeenAt.UTC(),
		IdleExpiresAt: row.IdleExpiresAt.UTC(),
		ExpiresAt:     row.ExpiresAt.UTC(),
		RevokedAt:     revokedAt,
		Active:        sessionActive(row.RevokedAt, row.IdleExpiresAt, row.ExpiresAt, now),
	}
}

func adminSessionResponseFromGetRow(row dbgen.GetUserSessionWithUserRow, now time.Time) adminSessionResponse {
	revokedAt := timePtrFromNull(row.RevokedAt)
	return adminSessionResponse{
		ID:            row.ID,
		UserID:        row.UserID,
		Username:      row.Username,
		DisplayName:   row.DisplayName,
		IPAddress:     optionalStringFromNull(row.IpAddress),
		UserAgent:     optionalStringFromNull(row.UserAgent),
		CreatedAt:     row.CreatedAt.UTC(),
		LastSeenAt:    row.LastSeenAt.UTC(),
		IdleExpiresAt: row.IdleExpiresAt.UTC(),
		ExpiresAt:     row.ExpiresAt.UTC(),
		RevokedAt:     revokedAt,
		Active:        sessionActive(row.RevokedAt, row.IdleExpiresAt, row.ExpiresAt, now),
	}
}

func sessionActive(revokedAt sql.NullTime, idleExpiresAt time.Time, expiresAt time.Time, now time.Time) bool {
	return !revokedAt.Valid && idleExpiresAt.UTC().After(now.UTC()) && expiresAt.UTC().After(now.UTC())
}

func timePtrFromNull(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}
