package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
)

func NewRouter(settings config.Settings) http.Handler {
	router := chi.NewRouter()
	router.Use(RequestBodyLimit(settings.MaxReportUploadBytes))
	router.Get("/healthz", healthz)
	mountFrontend(router, settings.FrontendDist)
	return router
}
