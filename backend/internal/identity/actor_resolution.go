package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

const (
	ActorTypeUser    = "user"
	ActorTypeMachine = "machine"

	AuthMethodSession     = "session"
	AuthMethodBearerToken = "bearer_token"
)

type ActorCredentials struct {
	BearerToken        *string
	SessionCookie      *string
	Now                time.Time
	IdleTimeoutMinutes int
}

func ResolveAuthenticatedActor(
	ctx context.Context,
	conn *sql.DB,
	credentials ActorCredentials,
) (*AuthenticatedActor, error) {
	bearerPresent := credentials.BearerToken != nil
	sessionPresent := credentials.SessionCookie != nil
	mixedPresent := bearerPresent && sessionPresent

	if bearerPresent {
		token, err := VerifyMachineAccessToken(ctx, conn, *credentials.BearerToken, credentials.Now)
		if err != nil {
			return nil, err
		}
		if token == nil {
			return nil, nil
		}
		queries := dbgen.New(conn)
		credential, err := queries.GetMachineCredential(ctx, token.MachineCredentialID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &AuthenticatedActor{
			ActorType:               ActorTypeMachine,
			ActorID:                 credential.ID,
			DisplayName:             credential.Name,
			PrincipalType:           PrincipalTypeMachine,
			PrincipalID:             credential.ID,
			AuthMethod:              AuthMethodBearerToken,
			MachineTokenID:          &token.ID,
			MixedCredentialsPresent: mixedPresent,
			BearerTokenPresent:      true,
			SessionCookiePresent:    sessionPresent,
		}, nil
	}

	if sessionPresent {
		session, err := GetActiveSession(ctx, conn, *credentials.SessionCookie, credentials.Now, credentials.IdleTimeoutMinutes)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, nil
		}
		queries := dbgen.New(conn)
		user, err := queries.GetUser(ctx, session.UserID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !user.IsActive {
			return nil, nil
		}
		return &AuthenticatedActor{
			ActorType:            ActorTypeUser,
			ActorID:              user.ID,
			DisplayName:          user.DisplayName,
			PrincipalType:        PrincipalTypeUser,
			PrincipalID:          user.ID,
			AuthMethod:           AuthMethodSession,
			SessionID:            &session.ID,
			BearerTokenPresent:   false,
			SessionCookiePresent: true,
		}, nil
	}

	return nil, nil
}
