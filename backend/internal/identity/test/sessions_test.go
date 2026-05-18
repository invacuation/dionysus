package identity_test

import (
	"context"
	"database/sql"
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestGetActiveSessionTouchesValidSession(t *testing.T) {
	conn := openSessionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertUserSession(t, conn, userSessionFixture{
		ID:            "session-1",
		UserID:        "user-1",
		RawToken:      "raw-token",
		ExpiresAt:     now.Add(2 * time.Hour),
		IdleExpiresAt: now.Add(5 * time.Minute),
		LastSeenAt:    now.Add(-10 * time.Minute),
		CreatedAt:     now.Add(-20 * time.Minute),
		UpdatedAt:     now.Add(-20 * time.Minute),
	})

	session, err := GetActiveSession(context.Background(), conn, "raw-token", now, 30)
	if err != nil {
		t.Fatalf("GetActiveSession() returned error: %v", err)
	}
	if session == nil {
		t.Fatal("GetActiveSession() = nil, want session")
	}
	if session.ID != "session-1" {
		t.Fatalf("session ID = %q, want session-1", session.ID)
	}
	if !session.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %s, want %s", session.LastSeenAt, now)
	}
	wantIdleExpiry := now.Add(30 * time.Minute)
	if !session.IdleExpiresAt.Equal(wantIdleExpiry) {
		t.Fatalf("IdleExpiresAt = %s, want %s", session.IdleExpiresAt, wantIdleExpiry)
	}
}

func TestGetActiveSessionCapsIdleExpiryAtAbsoluteExpiry(t *testing.T) {
	conn := openSessionTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)
	insertUserSession(t, conn, userSessionFixture{
		ID:            "session-1",
		UserID:        "user-1",
		RawToken:      "raw-token",
		ExpiresAt:     expiresAt,
		IdleExpiresAt: now.Add(5 * time.Minute),
		LastSeenAt:    now.Add(-10 * time.Minute),
		CreatedAt:     now.Add(-20 * time.Minute),
		UpdatedAt:     now.Add(-20 * time.Minute),
	})

	session, err := GetActiveSession(context.Background(), conn, "raw-token", now, 30)
	if err != nil {
		t.Fatalf("GetActiveSession() returned error: %v", err)
	}
	if session == nil {
		t.Fatal("GetActiveSession() = nil, want session")
	}
	if !session.IdleExpiresAt.Equal(expiresAt) {
		t.Fatalf("IdleExpiresAt = %s, want %s", session.IdleExpiresAt, expiresAt)
	}
}

func TestGetActiveSessionRejectsInactiveSessions(t *testing.T) {
	tests := []struct {
		name    string
		fixture userSessionFixture
	}{
		{
			name: "unknown token",
			fixture: userSessionFixture{
				ID:            "session-1",
				UserID:        "user-1",
				RawToken:      "different-token",
				ExpiresAt:     time.Date(2026, 5, 15, 14, 0, 0, 0, time.UTC),
				IdleExpiresAt: time.Date(2026, 5, 15, 12, 30, 0, 0, time.UTC),
			},
		},
		{
			name: "absolute expired",
			fixture: userSessionFixture{
				ID:            "session-1",
				UserID:        "user-1",
				RawToken:      "raw-token",
				ExpiresAt:     time.Date(2026, 5, 15, 11, 59, 0, 0, time.UTC),
				IdleExpiresAt: time.Date(2026, 5, 15, 12, 30, 0, 0, time.UTC),
			},
		},
		{
			name: "idle expired",
			fixture: userSessionFixture{
				ID:            "session-1",
				UserID:        "user-1",
				RawToken:      "raw-token",
				ExpiresAt:     time.Date(2026, 5, 15, 14, 0, 0, 0, time.UTC),
				IdleExpiresAt: time.Date(2026, 5, 15, 11, 59, 0, 0, time.UTC),
			},
		},
		{
			name: "revoked",
			fixture: userSessionFixture{
				ID:            "session-1",
				UserID:        "user-1",
				RawToken:      "raw-token",
				ExpiresAt:     time.Date(2026, 5, 15, 14, 0, 0, 0, time.UTC),
				IdleExpiresAt: time.Date(2026, 5, 15, 12, 30, 0, 0, time.UTC),
				RevokedAt:     sql.NullTime{Time: time.Date(2026, 5, 15, 11, 0, 0, 0, time.UTC), Valid: true},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := openSessionTestDB(t)
			now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
			test.fixture.CreatedAt = now.Add(-20 * time.Minute)
			test.fixture.UpdatedAt = now.Add(-20 * time.Minute)
			test.fixture.LastSeenAt = now.Add(-10 * time.Minute)
			insertUserSession(t, conn, test.fixture)

			session, err := GetActiveSession(context.Background(), conn, "raw-token", now, 30)
			if err != nil {
				t.Fatalf("GetActiveSession() returned error: %v", err)
			}
			if session != nil {
				t.Fatalf("GetActiveSession() = %#v, want nil", session)
			}
		})
	}
}

func openSessionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(
		context.Background(),
		`CREATE TABLE user_sessions (
			id VARCHAR PRIMARY KEY NOT NULL,
			user_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			user_agent TEXT,
			ip_address VARCHAR(64),
			expires_at DATETIME NOT NULL,
			idle_expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			last_seen_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	); err != nil {
		t.Fatalf("create user_sessions: %v", err)
	}
	return conn
}

type userSessionFixture struct {
	ID            string
	UserID        string
	RawToken      string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
	RevokedAt     sql.NullTime
	LastSeenAt    time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func insertUserSession(t *testing.T, conn *sql.DB, fixture userSessionFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO user_sessions (
			id,
			user_id,
			token_digest,
			expires_at,
			idle_expires_at,
			revoked_at,
			last_seen_at,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.UserID,
		security.TokenDigest(fixture.RawToken),
		fixture.ExpiresAt,
		fixture.IdleExpiresAt,
		fixture.RevokedAt,
		fixture.LastSeenAt,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert user session: %v", err)
	}
}
