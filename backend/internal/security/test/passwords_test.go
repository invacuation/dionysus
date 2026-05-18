package security_test

import (
	. "github.com/invacuation/dionysus/backend/internal/security"
	"testing"
)

const pythonArgon2Hash = "$argon2id$v=19$m=65536,t=3,p=4$QuVbsCm0NDtiCTn5MdE0uw$NLEfzmIHyfK15B1McgJvPtRY4OTcNkq6/qH7KRGzfHU"

func TestVerifyPasswordAcceptsPythonArgon2Hash(t *testing.T) {
	if !VerifyPassword("correct horse battery staple", pythonArgon2Hash) {
		t.Fatal("VerifyPassword() = false, want true")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	if VerifyPassword("wrong password", pythonArgon2Hash) {
		t.Fatal("VerifyPassword() = true, want false")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	if VerifyPassword("password", "not-an-argon2-hash") {
		t.Fatal("VerifyPassword() = true, want false")
	}
}
