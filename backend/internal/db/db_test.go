package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

func TestDriverAndDSNNormalizesSQLiteURL(t *testing.T) {
	driver, dsn, err := DriverAndDSN("sqlite:///../var/dionysus.db")
	if err != nil {
		t.Fatalf("DriverAndDSN() returned error: %v", err)
	}

	if driver != "sqlite" {
		t.Fatalf("driver = %q, want sqlite", driver)
	}
	if dsn != "../var/dionysus.db" {
		t.Fatalf("dsn = %q, want ../var/dionysus.db", dsn)
	}
}

func TestDriverAndDSNNormalizesSQLiteMemoryURL(t *testing.T) {
	driver, dsn, err := DriverAndDSN("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("DriverAndDSN() returned error: %v", err)
	}

	if driver != "sqlite" {
		t.Fatalf("driver = %q, want sqlite", driver)
	}
	if dsn != ":memory:" {
		t.Fatalf("dsn = %q, want :memory:", dsn)
	}
}

func TestDriverAndDSNNormalizesPythonPostgresURL(t *testing.T) {
	driver, dsn, err := DriverAndDSN("postgresql+psycopg://user:pass@db:5432/dionysus")
	if err != nil {
		t.Fatalf("DriverAndDSN() returned error: %v", err)
	}

	if driver != "pgx" {
		t.Fatalf("driver = %q, want pgx", driver)
	}
	if dsn != "postgresql://user:pass@db:5432/dionysus" {
		t.Fatalf("dsn = %q, want postgresql://user:pass@db:5432/dionysus", dsn)
	}
}

func TestOpenSQLiteMemory(t *testing.T) {
	conn, err := Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("Open() returned error: %v", err)
	}
	defer conn.Close()

	if err := conn.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() returned error: %v", err)
	}
}

func TestGeneratedSettingsQueryReadsSingleton(t *testing.T) {
	conn, err := Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("Open() returned error: %v", err)
	}
	defer conn.Close()
	createAppSecuritySettingsTable(t, conn)

	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO app_security_settings (
			id,
			force_peer_review_for_status_changes,
			session_idle_timeout_minutes,
			session_absolute_timeout_minutes,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		"default",
		true,
		45,
		480,
		now,
		now,
	); err != nil {
		t.Fatalf("insert settings: %v", err)
	}

	settings, err := dbgen.New(conn).GetAppSecuritySettings(context.Background(), "default")
	if err != nil {
		t.Fatalf("GetAppSecuritySettings() returned error: %v", err)
	}

	if settings.ID != "default" {
		t.Fatalf("ID = %q, want default", settings.ID)
	}
	if !settings.ForcePeerReviewForStatusChanges {
		t.Fatal("ForcePeerReviewForStatusChanges = false, want true")
	}
	if !settings.SessionIdleTimeoutMinutes.Valid || settings.SessionIdleTimeoutMinutes.Int64 != 45 {
		t.Fatalf("SessionIdleTimeoutMinutes = %#v, want valid 45", settings.SessionIdleTimeoutMinutes)
	}
}

func createAppSecuritySettingsTable(t *testing.T, conn *sql.DB) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`CREATE TABLE app_security_settings (
			id VARCHAR(50) PRIMARY KEY NOT NULL,
			force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
			session_idle_timeout_minutes INTEGER,
			session_absolute_timeout_minutes INTEGER,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	); err != nil {
		t.Fatalf("create settings table: %v", err)
	}
}
