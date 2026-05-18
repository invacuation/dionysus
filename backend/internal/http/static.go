package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

var frontendRoutePrefixes = map[string]struct{}{
	"admin":     {},
	"findings":  {},
	"imports":   {},
	"inventory": {},
}

// This method mounts the frontend assets and index.html to the Chi router.
// We do this so that the backend can serve the frontend without needing a separate web server or build step.
func mountFrontend(router chi.Router, frontendDist string) {
	// Serve the assets directory
	if frontendDist == "" {
		frontendDist = "../frontend/dist"
	}
	assetsDir := filepath.Join(frontendDist, "assets")
	if info, err := os.Stat(assetsDir); err == nil && info.IsDir() {
		router.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(assetsDir))))
	}

	// Serve the index.html file for all routes
	// This allows the frontend to handle routing on the client side
	serveIndex := func(response http.ResponseWriter, request *http.Request) {
		indexPath := filepath.Join(frontendDist, "index.html")
		if _, err := os.Stat(indexPath); err != nil {
			http.NotFound(response, request)
			return
		}
		http.ServeFile(response, request, indexPath)
	}

	// Map all backend routes to the index.html file, to allow the frontend
	// to handle routing instead
	router.Get("/", serveIndex)
	router.Get("/admin", serveIndex)
	router.Get("/findings", serveIndex)
	router.Get("/imports", serveIndex)
	router.Get("/inventory", serveIndex)
	router.Get("/login", serveIndex)

	router.Get("/*", func(response http.ResponseWriter, request *http.Request) {
		path := strings.TrimPrefix(request.URL.Path, "/")
		firstSegment, _, _ := strings.Cut(path, "/")
		if _, ok := frontendRoutePrefixes[firstSegment]; !ok {
			http.NotFound(response, request)
			return
		}
		serveIndex(response, request)
	})
}
