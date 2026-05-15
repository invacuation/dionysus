package httpapi

import (
	"net"
	"net/http"

	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func recordActorAuditEvent(r *http.Request, deps Dependencies, actor identity.AuthenticatedActor, event auditlog.Event) error {
	event.ActorPrincipalType = stringPtr(actor.PrincipalType)
	event.ActorPrincipalID = stringPtr(actor.PrincipalID)
	event.ActorDisplay = stringPtr(actor.DisplayName)
	event.IPAddress = clientHost(r)
	event.UserAgent = optionalHeader(r, "User-Agent")
	_, err := auditlog.RecordEvent(r.Context(), deps.DB, event)
	return err
}

func stringPtr(value string) *string {
	return &value
}

func optionalHeader(r *http.Request, name string) *string {
	value := r.Header.Get(name)
	if value == "" {
		return nil
	}
	return &value
}

func clientHost(r *http.Request) *string {
	if r.RemoteAddr == "" {
		return nil
	}
	host := r.RemoteAddr
	if parsedHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsedHost
	}
	return &host
}
