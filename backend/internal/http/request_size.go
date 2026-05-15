package httpapi

import (
	"net/http"

	"github.com/invacuation/dionysus/backend/internal/config"
)

func RequestBodyLimit(maxBodyBytes int) func(http.Handler) http.Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = config.DefaultMaxReportUploadBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.ContentLength > int64(maxBodyBytes) {
				http.Error(response, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			request.Body = http.MaxBytesReader(response, request.Body, int64(maxBodyBytes))
			next.ServeHTTP(response, request)
		})
	}
}
