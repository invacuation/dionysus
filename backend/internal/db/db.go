package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = "001"

//go:embed schema.sql
var schemaSQL string

var connectionDrivers sync.Map

func Open(databaseURL string) (*sql.DB, error) {
	driver, dsn, err := DriverAndDSN(databaseURL)
	if err != nil {
		return nil, err
	}
	conn, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if driver == "sqlite" {
		conn.SetMaxOpenConns(1)
		conn.SetMaxIdleConns(1)
	}
	connectionDrivers.Store(conn, driver)
	return conn, nil
}

func Migrate(ctx context.Context, conn *sql.DB) error {
	driver, err := driverFor(conn)
	if err != nil {
		return err
	}
	applied, err := migrationApplied(ctx, conn, driver, schemaVersion)
	if err != nil {
		return err
	}
	if applied {
		return nil
	}
	empty, err := databaseEmpty(ctx, conn, driver)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("database has existing tables but no Go migration marker")
	}
	if _, err := conn.ExecContext(ctx, initialSchemaSQL(driver)); err != nil {
		return fmt.Errorf("apply schema migration: %w", err)
	}
	if err := ensureSchemaMigrations(ctx, conn, driver); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := conn.ExecContext(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", schemaVersion, now); err != nil {
		return fmt.Errorf("record schema migration: %w", err)
	}
	return nil
}

func ensureSchemaMigrations(ctx context.Context, conn *sql.DB, driver string) error {
	appliedAtType := "DATETIME"
	if driver == "pgx-qmark" {
		appliedAtType = "TIMESTAMPTZ"
	}
	statement := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(120) PRIMARY KEY NOT NULL,
		applied_at %s NOT NULL
	)`, appliedAtType)
	if _, err := conn.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func migrationApplied(ctx context.Context, conn *sql.DB, driver string, version string) (bool, error) {
	hasTable, err := tableExists(ctx, conn, driver, "schema_migrations")
	if err != nil {
		return false, err
	}
	if !hasTable {
		return false, nil
	}
	var found string
	if err := conn.QueryRowContext(ctx, "SELECT version FROM schema_migrations WHERE version = ?", version).Scan(&found); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("read schema migration: %w", err)
	}
	return true, nil
}

func databaseEmpty(ctx context.Context, conn *sql.DB, driver string) (bool, error) {
	query := "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
	if driver == "pgx-qmark" {
		query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
	}
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return false, fmt.Errorf("list database tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, fmt.Errorf("scan database table: %w", err)
		}
		if name != "schema_migrations" {
			return false, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate database tables: %w", err)
	}
	return true, nil
}

func tableExists(ctx context.Context, conn *sql.DB, driver string, name string) (bool, error) {
	var found string
	query := "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
	if driver == "pgx-qmark" {
		query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ?"
	}
	err := conn.QueryRowContext(ctx, query, name).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check table %s: %w", name, err)
	}
	return true, nil
}

func driverFor(conn *sql.DB) (string, error) {
	if driver, ok := connectionDrivers.Load(conn); ok {
		if driverName, ok := driver.(string); ok {
			return driverName, nil
		}
	}
	return "", fmt.Errorf("unknown database driver for %s; open connections with db.Open", reflect.TypeOf(conn))
}

func initialSchemaSQL(driver string) string {
	if driver != "pgx-qmark" {
		return schemaSQL
	}
	return strings.ReplaceAll(schemaSQL, "DATETIME", "TIMESTAMPTZ")
}

func DriverAndDSN(databaseURL string) (string, string, error) {
	switch {
	case databaseURL == "sqlite:///:memory:":
		return "sqlite", ":memory:", nil
	case strings.HasPrefix(databaseURL, "sqlite:///"):
		return "sqlite", strings.TrimPrefix(databaseURL, "sqlite:///"), nil
	case strings.HasPrefix(databaseURL, "postgresql+psycopg://"):
		return "pgx-qmark", "postgresql://" + strings.TrimPrefix(databaseURL, "postgresql+psycopg://"), nil
	case strings.HasPrefix(databaseURL, "postgresql://"):
		return "pgx-qmark", databaseURL, nil
	case strings.HasPrefix(databaseURL, "postgres://"):
		return "pgx-qmark", databaseURL, nil
	default:
		return "", "", fmt.Errorf("unsupported database URL: %s", databaseURL)
	}
}
