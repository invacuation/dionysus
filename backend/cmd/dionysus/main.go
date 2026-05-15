package main

import (
	"log"
	"net/http"

	"github.com/invacuation/dionysus/backend/internal/app"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db"
	httpapi "github.com/invacuation/dionysus/backend/internal/http"
)

func main() {
	settings, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	conn, err := db.Open(settings.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("close database: %v", err)
		}
	}()

	server := &http.Server{
		Addr:    ":8000",
		Handler: app.New(settings, httpapi.WithDB(conn)),
	}
	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
