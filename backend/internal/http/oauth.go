package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const (
	clientCredentialsGrant = "client_credentials"
	bearerAuthScheme       = "bearer"
)

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func mountOAuthRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Post("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		createMachineToken(w, r, settings, deps)
	})
}

// Create a new machine token, given a valid client ID and secret.
// This is used for machine-to-machine authentication.
func createMachineToken(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if deps.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}
	credentials, ok := tokenRequestFromRequest(w, r)
	if !ok {
		return
	}
	if credentials.GrantType != clientCredentialsGrant {
		writeError(w, http.StatusBadRequest, "Unsupported grant_type")
		return
	}

	tokenPair, err := identity.ExchangeMachineClientSecret(r.Context(), deps.DB, identity.MachineClientSecretExchange{
		ClientID:                credentials.ClientID,
		ClientSecret:            credentials.ClientSecret,
		Now:                     time.Now().UTC(),
		AccessExpiresInMinutes:  settings.MachineAccessTokenExpiresMinutes,
		RefreshExpiresInMinutes: settings.MachineRefreshTokenExpiresMinutes,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Unable to create machine token!")
		return
	}
	if tokenPair == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "Invalid client credentials")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:      tokenPair.AccessToken,
		TokenType:        bearerAuthScheme,
		ExpiresIn:        settings.MachineAccessTokenExpiresMinutes * 60,
		RefreshToken:     tokenPair.RefreshToken,
		RefreshExpiresIn: settings.MachineRefreshTokenExpiresMinutes * 60,
	})
}

// This method retrieves token request (i.e. client ID and secret) from either a JSON body or form values, depending on the Content-Type header of the request.
func tokenRequestFromRequest(w http.ResponseWriter, r *http.Request) (tokenRequest, bool) {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType == "application/x-www-form-urlencoded" || contentType == "multipart/form-data" {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "Invalid token request")
			return tokenRequest{}, false
		}
		return tokenRequest{
			GrantType:    r.Form.Get("grant_type"),
			ClientID:     r.Form.Get("client_id"),
			ClientSecret: r.Form.Get("client_secret"),
		}, true
	}

	var request tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid token request")
		return tokenRequest{}, false
	}
	if request.GrantType == "" || request.ClientID == "" || request.ClientSecret == "" {
		writeError(w, http.StatusUnprocessableEntity, "Invalid token request")
		return tokenRequest{}, false
	}
	return request, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, struct {
		Detail string `json:"detail"`
	}{Detail: detail})
}
