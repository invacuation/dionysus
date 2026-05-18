package identity_test

import (
	"context"
	"database/sql"
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestRefreshMachineTokenRotatesRefreshToken(t *testing.T) {
	conn := openMachineTestDB(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	insertMachineCredential(t, conn, machineCredentialFixture{
		ID:                 "machine-1",
		Name:               "trivy-uploader",
		ClientID:           "client-1",
		ClientSecretDigest: security.TokenDigest("client-secret"),
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})
	firstPair, err := ExchangeMachineClientSecret(context.Background(), conn, MachineClientSecretExchange{
		ClientID:                "client-1",
		ClientSecret:            "client-secret",
		Now:                     now,
		AccessExpiresInMinutes:  15,
		RefreshExpiresInMinutes: 60,
	})
	if err != nil {
		t.Fatalf("ExchangeMachineClientSecret() returned error: %v", err)
	}
	if firstPair == nil {
		t.Fatal("ExchangeMachineClientSecret() = nil, want token pair")
	}

	rotated, err := RefreshMachineToken(context.Background(), conn, MachineRefreshTokenExchange{
		RawRefreshToken:         firstPair.RefreshToken,
		Now:                     now.Add(5 * time.Minute),
		AccessExpiresInMinutes:  15,
		RefreshExpiresInMinutes: 60,
	})
	if err != nil {
		t.Fatalf("RefreshMachineToken() returned error: %v", err)
	}
	if rotated == nil {
		t.Fatal("RefreshMachineToken() = nil, want rotated pair")
	}
	if rotated.AccessToken == firstPair.AccessToken {
		t.Fatal("rotated access token reused old access token")
	}
	if rotated.RefreshToken == firstPair.RefreshToken {
		t.Fatal("rotated refresh token reused old refresh token")
	}
	if !rotated.AccessTokenRecord.ExpiresAt.Equal(now.Add(20 * time.Minute)) {
		t.Fatalf("access expiry = %s, want %s", rotated.AccessTokenRecord.ExpiresAt, now.Add(20*time.Minute))
	}
	assertMachineTokenCounts(t, conn, 2, 2)
	assertRefreshTokenRevoked(t, conn, firstPair.RefreshTokenRecord.ID, now.Add(5*time.Minute))

	reused, err := RefreshMachineToken(context.Background(), conn, MachineRefreshTokenExchange{
		RawRefreshToken:         firstPair.RefreshToken,
		Now:                     now.Add(6 * time.Minute),
		AccessExpiresInMinutes:  15,
		RefreshExpiresInMinutes: 60,
	})
	if err != nil {
		t.Fatalf("RefreshMachineToken() returned error for reused token: %v", err)
	}
	if reused != nil {
		t.Fatalf("RefreshMachineToken() reused revoked token = %#v, want nil", reused)
	}
}

func TestRefreshMachineTokenRejectsInactiveRefreshTokenOrCredential(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		credential machineCredentialFixture
		refresh    machineRefreshTokenFixture
		rawToken   string
	}{
		{
			name:       "unknown token",
			credential: machineCredentialFixture{ID: "machine-1", IsActive: true},
			refresh:    machineRefreshTokenFixture{ID: "refresh-1", MachineCredentialID: "machine-1", RawToken: "different-token", ExpiresAt: now.Add(time.Hour)},
			rawToken:   "raw-refresh",
		},
		{
			name:       "revoked token",
			credential: machineCredentialFixture{ID: "machine-1", IsActive: true},
			refresh: machineRefreshTokenFixture{
				ID:                  "refresh-1",
				MachineCredentialID: "machine-1",
				RawToken:            "raw-refresh",
				ExpiresAt:           now.Add(time.Hour),
				RevokedAt:           sql.NullTime{Time: now.Add(-time.Minute), Valid: true},
			},
			rawToken: "raw-refresh",
		},
		{
			name:       "expired token",
			credential: machineCredentialFixture{ID: "machine-1", IsActive: true},
			refresh:    machineRefreshTokenFixture{ID: "refresh-1", MachineCredentialID: "machine-1", RawToken: "raw-refresh", ExpiresAt: now},
			rawToken:   "raw-refresh",
		},
		{
			name:       "inactive credential",
			credential: machineCredentialFixture{ID: "machine-1", IsActive: false},
			refresh:    machineRefreshTokenFixture{ID: "refresh-1", MachineCredentialID: "machine-1", RawToken: "raw-refresh", ExpiresAt: now.Add(time.Hour)},
			rawToken:   "raw-refresh",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := openMachineTestDB(t)
			test.credential.Name = "trivy-uploader"
			test.credential.ClientID = "client-1"
			test.credential.ClientSecretDigest = security.TokenDigest("client-secret")
			test.credential.CreatedAt = now.Add(-time.Hour)
			test.credential.UpdatedAt = now.Add(-time.Hour)
			insertMachineCredential(t, conn, test.credential)
			test.refresh.CreatedAt = now.Add(-time.Minute)
			test.refresh.UpdatedAt = now.Add(-time.Minute)
			insertMachineRefreshToken(t, conn, test.refresh)

			pair, err := RefreshMachineToken(context.Background(), conn, MachineRefreshTokenExchange{
				RawRefreshToken:         test.rawToken,
				Now:                     now,
				AccessExpiresInMinutes:  15,
				RefreshExpiresInMinutes: 60,
			})
			if err != nil {
				t.Fatalf("RefreshMachineToken() returned error: %v", err)
			}
			if pair != nil {
				t.Fatalf("RefreshMachineToken() = %#v, want nil", pair)
			}
			assertMachineTokenCounts(t, conn, 0, 1)
		})
	}
}
