package db

import "strings"

// sqliteSchemaSQL adapts the canonical PostgreSQL schema for SQLite.
func sqliteSchemaSQL(postgresSQL string) string {
	return strings.ReplaceAll(postgresSQL, "TIMESTAMPTZ", "DATETIME")
}
