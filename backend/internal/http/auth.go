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

const sessionCookieName = "dionysus_session"

type actorResponse struct {
	ActorType               string  `json:"actor_type"`
	ActorID                 string  `json:"actor_id"`
	DisplayName             string  `json:"display_name"`
	PrincipalType           string  `json:"principal_type"`
	PrincipalID             string  `json:"principal_id"`
	AuthMethod              string  `json:"auth_method"`
	SessionID               *string `json:"session_id"`
	MachineTokenID          *string `json:"machine_token_id"`
	MixedCredentialsPresent bool    `json:"mixed_credentials_present"`
	BearerTokenPresent      bool    `json:"bearer_token_present"`
	SessionCookiePresent    bool    `json:"session_cookie_present"`
	LocalAuthEnabled        bool    `json:"local_auth_enabled"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func mountAuthRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Post("/api/auth/session", func(w http.ResponseWriter, r *http.Request) {
		createBrowserSession(w, r, settings, deps)
	})
	router.Delete("/api/auth/session", func(w http.ResponseWriter, r *http.Request) {
		deleteBrowserSession(w, r, settings, deps)
	})
	router.Get("/api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		getCurrentActor(w, r, settings, deps)
	})
	router.Patch("/api/auth/password", func(w http.ResponseWriter, r *http.Request) {
		changeCurrentUserPassword(w, r, settings, deps)
	})
}

func createBrowserSession(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}
	if !settings.LocalAuthEnabled {
		writeError(w, http.StatusForbidden, "Local authentication is disabled")
		return
	}
	var credentials loginRequest
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid login request")
		return
	}
	user, err := identity.AuthenticateUser(r.Context(), deps.DB, credentials.Username, credentials.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if user == nil {
		if _, err := auditlog.RecordEvent(r.Context(), deps.DB, auditlog.Event{
			Type:      "auth.login.failure",
			IPAddress: clientHost(r),
			UserAgent: optionalHeader(r, "User-Agent"),
			Metadata:  map[string]any{"username": credentials.Username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}
	userAgent := r.Header.Get("User-Agent")
	rawToken, session, err := identity.CreateSession(
		r.Context(),
		deps.DB,
		*user,
		time.Now().UTC(),
		settings.SessionIdleTimeoutMinutes,
		settings.SessionAbsoluteTimeoutMinutes,
		&userAgent,
		nil,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if _, err := auditlog.RecordEvent(r.Context(), deps.DB, auditlog.Event{
		Type:               "auth.login.success",
		ActorPrincipalType: stringPtr(identity.PrincipalTypeUser),
		ActorPrincipalID:   stringPtr(user.ID),
		ActorDisplay:       stringPtr(user.DisplayName),
		TargetType:         stringPtr("session"),
		TargetID:           stringPtr(session.ID),
		IPAddress:          clientHost(r),
		UserAgent:          optionalHeader(r, "User-Agent"),
		Metadata:           map[string]any{"username": credentials.Username},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawToken,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	writeJSON(w, http.StatusOK, actorResponse{
		ActorType:               identity.ActorTypeUser,
		ActorID:                 user.ID,
		DisplayName:             user.DisplayName,
		PrincipalType:           identity.PrincipalTypeUser,
		PrincipalID:             user.ID,
		AuthMethod:              identity.AuthMethodSession,
		SessionID:               &session.ID,
		MixedCredentialsPresent: false,
		BearerTokenPresent:      false,
		SessionCookiePresent:    true,
		LocalAuthEnabled:        settings.LocalAuthEnabled,
	})
}

func deleteBrowserSession(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		session, err := identity.GetActiveSession(
			r.Context(),
			deps.DB,
			cookie.Value,
			time.Now().UTC(),
			settings.SessionIdleTimeoutMinutes,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if session != nil {
			if err := identity.RevokeSession(r.Context(), deps.DB, *session, time.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			user, _ := dbgen.New(deps.DB).GetUser(r.Context(), session.UserID)
			actorDisplay := ""
			if user.DisplayName != "" {
				actorDisplay = user.DisplayName
			}
			if _, err := auditlog.RecordEvent(r.Context(), deps.DB, auditlog.Event{
				Type:               "auth.logout",
				ActorPrincipalType: stringPtr(identity.PrincipalTypeUser),
				ActorPrincipalID:   stringPtr(session.UserID),
				ActorDisplay:       stringPtr(actorDisplay),
				TargetType:         stringPtr("session"),
				TargetID:           stringPtr(session.ID),
				IPAddress:          clientHost(r),
				UserAgent:          optionalHeader(r, "User-Agent"),
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	w.WriteHeader(http.StatusNoContent)
}

func getCurrentActor(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}

	bearerToken := identity.ParseBearerAuthorization(r.Header.Get("Authorization"))
	var sessionToken *string
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionToken = &cookie.Value
	}
	actor, err := identity.ResolveAuthenticatedActor(r.Context(), deps.DB, identity.ActorCredentials{
		BearerToken:        bearerToken,
		SessionCookie:      sessionToken,
		Now:                time.Now().UTC(),
		IdleTimeoutMinutes: settings.SessionIdleTimeoutMinutes,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if actor == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, actorResponse{
		ActorType:               actor.ActorType,
		ActorID:                 actor.ActorID,
		DisplayName:             actor.DisplayName,
		PrincipalType:           actor.PrincipalType,
		PrincipalID:             actor.PrincipalID,
		AuthMethod:              actor.AuthMethod,
		SessionID:               actor.SessionID,
		MachineTokenID:          actor.MachineTokenID,
		MixedCredentialsPresent: actor.MixedCredentialsPresent,
		BearerTokenPresent:      actor.BearerTokenPresent,
		SessionCookiePresent:    actor.SessionCookiePresent,
		LocalAuthEnabled:        settings.LocalAuthEnabled,
	})
}

func changeCurrentUserPassword(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}
	if !settings.LocalAuthEnabled {
		writeError(w, http.StatusForbidden, "Local authentication is disabled")
		return
	}
	actor, ok := authenticatedActorFromRequest(w, r, settings, deps)
	if !ok {
		return
	}
	if actor.ActorType != identity.ActorTypeUser {
		writeError(w, http.StatusForbidden, "Password changes require a user session")
		return
	}
	var payload passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid password change request")
		return
	}
	if err := identity.ChangeUserPassword(
		r.Context(),
		deps.DB,
		actor.ActorID,
		payload.CurrentPassword,
		payload.NewPassword,
		time.Now().UTC(),
	); err != nil {
		if err == identity.ErrCurrentPasswordIncorrect {
			writeError(w, http.StatusBadRequest, "Current password is incorrect")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "auth.password.change",
		TargetType: stringPtr("user"),
		TargetID:   stringPtr(actor.ActorID),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func authenticatedActorFromRequest(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) (*identity.AuthenticatedActor, bool) {
	bearerToken := identity.ParseBearerAuthorization(r.Header.Get("Authorization"))
	var sessionToken *string
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionToken = &cookie.Value
	}
	actor, err := identity.ResolveAuthenticatedActor(r.Context(), deps.DB, identity.ActorCredentials{
		BearerToken:        bearerToken,
		SessionCookie:      sessionToken,
		Now:                time.Now().UTC(),
		IdleTimeoutMinutes: settings.SessionIdleTimeoutMinutes,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if actor == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return nil, false
	}
	return actor, true
}
