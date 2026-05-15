package main

import (
	"log"
	"net/http"

	"github.com/invacuation/dionysus/backend/internal/app"
	"github.com/invacuation/dionysus/backend/internal/config"
)

func main() {
	settings, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	server := &http.Server{
		Addr:    ":8000",
		Handler: app.New(settings),
	}
	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
