package httpapi

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
)

type Dependencies struct {
	DB *sql.DB
}

type Option func(*Dependencies)

func WithDB(conn *sql.DB) Option {
	return func(deps *Dependencies) {
		deps.DB = conn
	}
}

func NewRouter(settings config.Settings, options ...Option) http.Handler {
	deps := Dependencies{}
	for _, option := range options {
		option(&deps)
	}

	router := chi.NewRouter()
	router.Use(RequestBodyLimit(settings.MaxReportUploadBytes))
	router.Get("/healthz", healthz)
	mountAuthRoutes(router, settings, deps)
	mountAccessRoutes(router, settings, deps)
	mountAdminSessionRoutes(router, settings, deps)
	mountAuditRoutes(router, settings, deps)
	mountMachineCredentialRoutes(router, settings, deps)
	mountPermissionTestRoutes(router, settings, deps)
	mountSecuritySettingsRoutes(router, settings, deps)
	mountOAuthRoutes(router, settings, deps)
	mountFrontend(router, settings.FrontendDist)
	return router
}
