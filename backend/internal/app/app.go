package app

import (
	"net/http"

	"github.com/invacuation/dionysus/backend/internal/config"
	httpapi "github.com/invacuation/dionysus/backend/internal/http"
)

func New(settings config.Settings, options ...httpapi.Option) http.Handler {
	return httpapi.NewRouter(settings, options...)
}
