package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/invacuation/dionysus/backend/internal/app"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db"
	httpapi "github.com/invacuation/dionysus/backend/internal/http"
	"github.com/invacuation/dionysus/backend/internal/identity"
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
	if err := db.Migrate(context.Background(), conn); err != nil {
		log.Fatalf("migrate database: %v", err)
	}
	if user, err := identity.BootstrapAdminFromSettings(context.Background(), conn, settings, time.Now().UTC()); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	} else if user != nil {
		log.Printf("bootstrapped admin user %s", user.Username)
	}

	server := &http.Server{
		Addr:    settings.HTTPAddr,
		Handler: app.New(settings, httpapi.WithDB(conn)),
	}
	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
