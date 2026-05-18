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

// Creates a new HTTP Router, mounting all of the routes needed for the application
// to work.
func NewRouter(settings config.Settings, options ...Option) http.Handler {
	deps := Dependencies{}
	for _, option := range options {
		option(&deps)
	}

	// Set up the new router
	router := chi.NewRouter()

	// Set the max request body size. This is primarily to prevent users from uploading huge reports
	router.Use(RequestBodyLimit(settings.MaxReportUploadBytes))

	// The healthcheck endpoint
	router.Get("/healthz", healthz)

	mountAuthRoutes(router, settings, deps)
	mountAccessRoutes(router, settings, deps)
	mountAdminSessionRoutes(router, settings, deps)
	mountAuditRoutes(router, settings, deps)
	mountFindingRoutes(router, settings, deps)
	mountImportRoutes(router, settings, deps)
	mountInventoryRoutes(router, settings, deps)
	mountMachineCredentialRoutes(router, settings, deps)
	mountOverviewRoutes(router, settings, deps)
	mountPermissionTestRoutes(router, settings, deps)
	mountSecuritySettingsRoutes(router, settings, deps)
	mountOAuthRoutes(router, settings, deps)
	mountFrontend(router, settings.FrontendDist)

	return router
}
