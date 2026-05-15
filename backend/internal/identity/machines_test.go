package identity

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db"
	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestVerifyMachineAccessTokenReturnsActiveToken(t *testing.T) {
	conn := openMachineTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertMachineCredential(t, conn, machineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-20 * time.Minute),
		UpdatedAt:          now.Add(-20 * time.Minute),
	})
	insertMachineToken(t, conn, machineTokenFixture{
		ID:                  "token-1",
		MachineCredentialID: "machine-1",
		RawToken:            "raw-token",
		ExpiresAt:           now.Add(15 * time.Minute),
		CreatedAt:           now.Add(-5 * time.Minute),
		UpdatedAt:           now.Add(-5 * time.Minute),
	})

	token, err := VerifyMachineAccessToken(context.Background(), conn, "raw-token", now)
	if err != nil {
		t.Fatalf("VerifyMachineAccessToken() returned error: %v", err)
	}
	if token == nil {
		t.Fatal("VerifyMachineAccessToken() = nil, want token")
	}
	if token.ID != "token-1" {
		t.Fatalf("token ID = %q, want token-1", token.ID)
	}
	if !token.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("ExpiresAt = %s, want %s", token.ExpiresAt, now.Add(15*time.Minute))
	}
}

func TestVerifyMachineAccessTokenRejectsInactiveTokenOrCredential(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		credential machineCredentialFixture
		token      machineTokenFixture
		rawToken   string
	}{
		{
			name: "unknown token",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				IsActive: true,
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "different-token",
				ExpiresAt:           now.Add(15 * time.Minute),
			},
			rawToken: "raw-token",
		},
		{
			name: "revoked token",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				IsActive: true,
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-token",
				ExpiresAt:           now.Add(15 * time.Minute),
				RevokedAt:           sql.NullTime{Time: now.Add(-time.Minute), Valid: true},
			},
			rawToken: "raw-token",
		},
		{
			name: "expired token",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				IsActive: true,
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-token",
				ExpiresAt:           now,
			},
			rawToken: "raw-token",
		},
		{
			name: "inactive credential",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				IsActive: false,
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-token",
				ExpiresAt:           now.Add(15 * time.Minute),
			},
			rawToken: "raw-token",
		},
		{
			name: "revoked credential",
			credential: machineCredentialFixture{
				ID:        "machine-1",
				IsActive:  true,
				RevokedAt: sql.NullTime{Time: now.Add(-time.Minute), Valid: true},
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-token",
				ExpiresAt:           now.Add(15 * time.Minute),
			},
			rawToken: "raw-token",
		},
		{
			name: "missing credential",
			credential: machineCredentialFixture{
				ID:       "",
				IsActive: true,
			},
			token: machineTokenFixture{
				ID:                  "token-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-token",
				ExpiresAt:           now.Add(15 * time.Minute),
			},
			rawToken: "raw-token",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := openMachineTestDB(t)
			test.credential.Name = "trivy-uploader"
			test.credential.ClientID = "client-1"
			test.credential.ClientSecretDigest = security.TokenDigest("client-secret")
			test.credential.CreatedAt = now.Add(-20 * time.Minute)
			test.credential.UpdatedAt = now.Add(-20 * time.Minute)
			test.token.CreatedAt = now.Add(-5 * time.Minute)
			test.token.UpdatedAt = now.Add(-5 * time.Minute)

			if test.credential.ID != "" {
				insertMachineCredential(t, conn, test.credential)
			}
			insertMachineToken(t, conn, test.token)

			token, err := VerifyMachineAccessToken(context.Background(), conn, test.rawToken, now)
			if err != nil {
				t.Fatalf("VerifyMachineAccessToken() returned error: %v", err)
			}
			if token != nil {
				t.Fatalf("VerifyMachineAccessToken() = %#v, want nil", token)
			}
		})
	}
}

func openMachineTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open("sqlite:///:memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(
		context.Background(),
		`CREATE TABLE machine_credentials (
			id VARCHAR PRIMARY KEY NOT NULL,
			name VARCHAR(150) NOT NULL,
			client_id VARCHAR(64) NOT NULL,
			client_secret_digest VARCHAR(64) NOT NULL,
			is_active BOOLEAN NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	); err != nil {
		t.Fatalf("create machine_credentials: %v", err)
	}
	if _, err := conn.ExecContext(
		context.Background(),
		`CREATE TABLE machine_tokens (
			id VARCHAR PRIMARY KEY NOT NULL,
			machine_credential_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	); err != nil {
		t.Fatalf("create machine_tokens: %v", err)
	}
	if _, err := conn.ExecContext(
		context.Background(),
		`CREATE TABLE machine_refresh_tokens (
			id VARCHAR PRIMARY KEY NOT NULL,
			machine_credential_id VARCHAR NOT NULL,
			token_digest VARCHAR(64) NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
	); err != nil {
		t.Fatalf("create machine_refresh_tokens: %v", err)
	}
	return conn
}

type machineCredentialFixture struct {
	ID                 string
	Name               string
	ClientID           string
	ClientSecretDigest string
	IsActive           bool
	RevokedAt          sql.NullTime
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func insertMachineCredential(t *testing.T, conn *sql.DB, fixture machineCredentialFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO machine_credentials (
			id,
			name,
			client_id,
			client_secret_digest,
			is_active,
			revoked_at,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.Name,
		fixture.ClientID,
		fixture.ClientSecretDigest,
		fixture.IsActive,
		fixture.RevokedAt,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert machine credential: %v", err)
	}
}

type machineTokenFixture struct {
	ID                  string
	MachineCredentialID string
	RawToken            string
	ExpiresAt           time.Time
	RevokedAt           sql.NullTime
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func insertMachineToken(t *testing.T, conn *sql.DB, fixture machineTokenFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO machine_tokens (
			id,
			machine_credential_id,
			token_digest,
			expires_at,
			revoked_at,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.MachineCredentialID,
		security.TokenDigest(fixture.RawToken),
		fixture.ExpiresAt,
		fixture.RevokedAt,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert machine token: %v", err)
	}
}

type machineRefreshTokenFixture struct {
	ID                  string
	MachineCredentialID string
	RawToken            string
	ExpiresAt           time.Time
	RevokedAt           sql.NullTime
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func insertMachineRefreshToken(t *testing.T, conn *sql.DB, fixture machineRefreshTokenFixture) {
	t.Helper()
	if _, err := conn.ExecContext(
		context.Background(),
		`INSERT INTO machine_refresh_tokens (
			id,
			machine_credential_id,
			token_digest,
			expires_at,
			revoked_at,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fixture.ID,
		fixture.MachineCredentialID,
		security.TokenDigest(fixture.RawToken),
		fixture.ExpiresAt,
		fixture.RevokedAt,
		fixture.CreatedAt,
		fixture.UpdatedAt,
	); err != nil {
		t.Fatalf("insert machine refresh token: %v", err)
	}
}

func assertRefreshTokenRevoked(t *testing.T, conn *sql.DB, id string, want time.Time) {
	t.Helper()
	var revokedAt sql.NullTime
	if err := conn.QueryRowContext(
		context.Background(),
		"SELECT revoked_at FROM machine_refresh_tokens WHERE id = ?",
		id,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("select refresh token revoked_at: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatal("refresh token revoked_at is NULL, want timestamp")
	}
	if !revokedAt.Time.Equal(want) {
		t.Fatalf("refresh token revoked_at = %s, want %s", revokedAt.Time, want)
	}
}

func assertMachineTokenCounts(t *testing.T, conn *sql.DB, wantAccess int, wantRefresh int) {
	t.Helper()
	var gotAccess int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM machine_tokens").Scan(&gotAccess); err != nil {
		t.Fatalf("count machine tokens: %v", err)
	}
	var gotRefresh int
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM machine_refresh_tokens").Scan(&gotRefresh); err != nil {
		t.Fatalf("count machine refresh tokens: %v", err)
	}
	if gotAccess != wantAccess || gotRefresh != wantRefresh {
		t.Fatalf("token counts = access %d refresh %d, want access %d refresh %d", gotAccess, gotRefresh, wantAccess, wantRefresh)
	}
}
