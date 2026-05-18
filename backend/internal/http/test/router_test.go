package httpapi_test

import (
	"encoding/json"
	. "github.com/invacuation/dionysus/backend/internal/http"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/invacuation/dionysus/backend/internal/config"
)

func TestRouterServesHealthz(t *testing.T) {
	router := NewRouter(config.Settings{})

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status body = %q, want ok", body["status"])
	}
}

func TestRouterServesFrontendIndexAtRoot(t *testing.T) {
	frontendDist := t.TempDir()
	writeFile(t, frontendDist+"/index.html", `<div id="root"></div>`)

	router := NewRouter(config.Settings{FrontendDist: frontendDist})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("body = %q, want React root", response.Body.String())
	}
}

func TestRouterServesFrontendIndexForKnownRoutes(t *testing.T) {
	frontendDist := t.TempDir()
	writeFile(t, frontendDist+"/index.html", `<div id="root"></div>`)

	router := NewRouter(config.Settings{FrontendDist: frontendDist})

	request := httptest.NewRequest(http.MethodGet, "/findings", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("body = %q, want React root", response.Body.String())
	}
}

func TestRouterServesFrontendAssets(t *testing.T) {
	frontendDist := t.TempDir()
	writeFile(t, frontendDist+"/index.html", `<div id="root"></div>`)
	writeFile(t, frontendDist+"/assets/app.js", `console.log("dionysus")`)

	router := NewRouter(config.Settings{FrontendDist: frontendDist})

	request := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `console.log("dionysus")`) {
		t.Fatalf("body = %q, want asset body", response.Body.String())
	}
}

func TestRouterDoesNotSwallowBackendPrefixes(t *testing.T) {
	frontendDist := t.TempDir()
	writeFile(t, frontendDist+"/index.html", `<div id="root"></div>`)

	router := NewRouter(config.Settings{FrontendDist: frontendDist})

	request := httptest.NewRequest(http.MethodGet, "/api/not-a-real-route", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestRouterRejectsOversizedRequestBody(t *testing.T) {
	router := NewRouter(config.Settings{MaxReportUploadBytes: 4})

	request := httptest.NewRequest(http.MethodPost, "/healthz", strings.NewReader("too large"))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
