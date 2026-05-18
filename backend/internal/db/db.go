package db

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

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
	return conn, nil
}

func DriverAndDSN(databaseURL string) (string, string, error) {
	switch {
	case databaseURL == "sqlite:///:memory:":
		return "sqlite", ":memory:", nil
	case strings.HasPrefix(databaseURL, "sqlite:///"):
		return "sqlite", strings.TrimPrefix(databaseURL, "sqlite:///"), nil
	case strings.HasPrefix(databaseURL, "postgresql+psycopg://"):
		return "pgx", "postgresql://" + strings.TrimPrefix(databaseURL, "postgresql+psycopg://"), nil
	case strings.HasPrefix(databaseURL, "postgresql://"):
		return "pgx", databaseURL, nil
	case strings.HasPrefix(databaseURL, "postgres://"):
		return "pgx", databaseURL, nil
	default:
		return "", "", fmt.Errorf("unsupported database URL: %s", databaseURL)
	}
}
