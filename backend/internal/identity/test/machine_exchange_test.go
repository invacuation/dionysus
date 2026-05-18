package identity_test

import (
	"context"
	"database/sql"
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/security"
)

func TestExchangeMachineClientSecretIssuesTokenPair(t *testing.T) {
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

	pair, err := ExchangeMachineClientSecret(context.Background(), conn, MachineClientSecretExchange{
		ClientID:                "client-1",
		ClientSecret:            "client-secret",
		Now:                     now,
		AccessExpiresInMinutes:  15,
		RefreshExpiresInMinutes: 60,
	})
	if err != nil {
		t.Fatalf("ExchangeMachineClientSecret() returned error: %v", err)
	}
	if pair == nil {
		t.Fatal("ExchangeMachineClientSecret() = nil, want token pair")
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("token pair contains empty raw token: %#v", pair)
	}
	if pair.AccessToken == pair.RefreshToken {
		t.Fatal("access token equals refresh token, want distinct bearer material")
	}
	if pair.AccessTokenRecord.TokenDigest == pair.AccessToken {
		t.Fatal("access token raw value was stored directly")
	}
	if pair.RefreshTokenRecord.TokenDigest == pair.RefreshToken {
		t.Fatal("refresh token raw value was stored directly")
	}
	if !pair.AccessTokenRecord.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("access expiry = %s, want %s", pair.AccessTokenRecord.ExpiresAt, now.Add(15*time.Minute))
	}
	if !pair.RefreshTokenRecord.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("refresh expiry = %s, want %s", pair.RefreshTokenRecord.ExpiresAt, now.Add(time.Hour))
	}

	verified, err := VerifyMachineAccessToken(context.Background(), conn, pair.AccessToken, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("VerifyMachineAccessToken() returned error: %v", err)
	}
	if verified == nil || verified.ID != pair.AccessTokenRecord.ID {
		t.Fatalf("verified token = %#v, want ID %s", verified, pair.AccessTokenRecord.ID)
	}
}

func TestExchangeMachineClientSecretRejectsInvalidCredential(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		credential machineCredentialFixture
		secret     string
	}{
		{
			name: "unknown client",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				ClientID: "different-client",
				IsActive: true,
			},
			secret: "client-secret",
		},
		{
			name: "bad secret",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				ClientID: "client-1",
				IsActive: true,
			},
			secret: "wrong-secret",
		},
		{
			name: "inactive credential",
			credential: machineCredentialFixture{
				ID:       "machine-1",
				ClientID: "client-1",
				IsActive: false,
			},
			secret: "client-secret",
		},
		{
			name: "revoked credential",
			credential: machineCredentialFixture{
				ID:        "machine-1",
				ClientID:  "client-1",
				IsActive:  true,
				RevokedAt: sql.NullTime{Time: now.Add(-time.Minute), Valid: true},
			},
			secret: "client-secret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := openMachineTestDB(t)
			test.credential.Name = "trivy-uploader"
			test.credential.ClientSecretDigest = security.TokenDigest("client-secret")
			test.credential.CreatedAt = now.Add(-time.Hour)
			test.credential.UpdatedAt = now.Add(-time.Hour)
			insertMachineCredential(t, conn, test.credential)

			pair, err := ExchangeMachineClientSecret(context.Background(), conn, MachineClientSecretExchange{
				ClientID:                "client-1",
				ClientSecret:            test.secret,
				Now:                     now,
				AccessExpiresInMinutes:  15,
				RefreshExpiresInMinutes: 60,
			})
			if err != nil {
				t.Fatalf("ExchangeMachineClientSecret() returned error: %v", err)
			}
			if pair != nil {
				t.Fatalf("ExchangeMachineClientSecret() = %#v, want nil", pair)
			}
			assertMachineTokenCounts(t, conn, 0, 0)
		})
	}
}
