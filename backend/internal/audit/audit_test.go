package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

func TestRecordEventRedactsSensitiveMetadata(t *testing.T) {
	conn := openAuditTestDB(t)

	event, err := RecordEvent(t.Context(), conn, Event{
		Type:             "auth.login.failure",
		ActorPrincipalID: ptr("principal-id"),
		Metadata: map[string]any{
			"username":    "alice",
			"password":    "not-stored",
			"nested":      map[string]any{"access_token": "also-not-stored", "safe": "kept"},
			"items":       []any{map[string]any{"client_secret": "hidden"}, map[string]any{"detail": "ok"}},
			"stack_trace": "Traceback with implementation detail",
			"raw_report":  map[string]any{"ArtifactName": "private-image"},
		},
		Now: time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("record event: %v", err)
	}

	if event.MetadataJson != `{"items":[{"client_secret":"[REDACTED]"},{"detail":"ok"}],"nested":{"access_token":"[REDACTED]","safe":"kept"},"password":"[REDACTED]","raw_report":"[REDACTED]","stack_trace":"[REDACTED]","username":"alice"}` {
		t.Fatalf("metadata_json = %s", event.MetadataJson)
	}
}

func TestRecordEventRejectsBlankEventType(t *testing.T) {
	conn := openAuditTestDB(t)

	if _, err := RecordEvent(t.Context(), conn, Event{Type: "  "}); err == nil {
		t.Fatal("err = nil, want error")
	}
}

func openAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(context.Background(), `CREATE TABLE audit_log_events (
		id VARCHAR PRIMARY KEY NOT NULL,
		event_type VARCHAR(120) NOT NULL,
		actor_principal_type VARCHAR(50),
		actor_principal_id VARCHAR(36),
		actor_display VARCHAR(255),
		target_type VARCHAR(120),
		target_id VARCHAR(255),
		project_id VARCHAR(36),
		ip_address VARCHAR(120),
		user_agent TEXT,
		metadata_json TEXT NOT NULL,
		created_at DATETIME NOT NULL
	)`); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	_ = dbgen.New(conn)
	return conn
}

func ptr(value string) *string {
	return &value
}
