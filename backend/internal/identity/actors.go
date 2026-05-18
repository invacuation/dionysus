package identity

import "strings"

func ParseBearerAuthorization(value string) *string {
	if value == "" {
		return nil
	}
	scheme, credentials, found := strings.Cut(value, " ")
	if strings.ToLower(scheme) != "bearer" {
		return nil
	}
	if !found {
		empty := ""
		return &empty
	}
	token := strings.TrimSpace(credentials)
	return &token
}
