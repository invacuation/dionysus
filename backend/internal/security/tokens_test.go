package security

import (
	"encoding/hex"
	"testing"
)

func TestTokenDigestMatchesPythonSHA256Hex(t *testing.T) {
	digest := TokenDigest("raw-token")

	want := "34d328009b123fbbb0dc93f18b3e6de1ecf7b1a5783c33dff7ffe1926f09e943"
	if digest != want {
		t.Fatalf("TokenDigest() = %q, want %q", digest, want)
	}
}

func TestGenerateTokenReturnsURLSafeRandomToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() returned error: %v", err)
	}

	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}
	if _, err := hex.DecodeString(TokenDigest(token)); err != nil {
		t.Fatalf("generated token digest is not hex: %v", err)
	}
}
