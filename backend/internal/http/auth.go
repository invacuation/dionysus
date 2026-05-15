package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
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

func mountAuthRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		getCurrentActor(w, r, settings, deps)
	})
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
