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

func mountFrontend(router chi.Router, frontendDist string) {
	if frontendDist == "" {
		frontendDist = "../frontend/dist"
	}
	assetsDir := filepath.Join(frontendDist, "assets")
	if info, err := os.Stat(assetsDir); err == nil && info.IsDir() {
		router.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(assetsDir))))
	}

	serveIndex := func(response http.ResponseWriter, request *http.Request) {
		indexPath := filepath.Join(frontendDist, "index.html")
		if _, err := os.Stat(indexPath); err != nil {
			http.NotFound(response, request)
			return
		}
		http.ServeFile(response, request, indexPath)
	}

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
