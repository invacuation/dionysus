package identity_test

import (
	. "github.com/invacuation/dionysus/backend/internal/identity"
	"testing"
)

func TestParseBearerAuthorization(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  *string
	}{
		{name: "empty", value: "", want: nil},
		{name: "different scheme", value: "Basic abc", want: nil},
		{name: "bearer token", value: "Bearer token-value", want: ptr("token-value")},
		{name: "case insensitive scheme", value: "bearer token-value", want: ptr("token-value")},
		{name: "trims token whitespace", value: "Bearer   token-value  ", want: ptr("token-value")},
		{name: "missing credentials", value: "Bearer", want: ptr("")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ParseBearerAuthorization(test.value)
			if test.want == nil {
				if got != nil {
					t.Fatalf("ParseBearerAuthorization() = %q, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("ParseBearerAuthorization() = nil, want value")
			}
			if *got != *test.want {
				t.Fatalf("ParseBearerAuthorization() = %q, want %q", *got, *test.want)
			}
		})
	}
}

func ptr(value string) *string {
	return &value
}
