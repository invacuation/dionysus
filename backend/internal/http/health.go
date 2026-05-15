package httpapi

import (
	"encoding/json"
	"net/http"
)

func healthz(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(map[string]string{"status": "ok"}); err != nil {
		http.Error(response, "failed to encode response", http.StatusInternalServerError)
	}
}
