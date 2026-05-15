package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
)

func NewRouter(_ config.Settings) http.Handler {
	router := chi.NewRouter()
	router.Get("/healthz", healthz)
	return router
}
