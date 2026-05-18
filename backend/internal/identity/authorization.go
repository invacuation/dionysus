package identity

import (
	"context"
	"database/sql"
	"errors"
)

const AdminPermission = "admin:*"

var ErrForbidden = errors.New("Forbidden")

type AuthenticatedActor struct {
	ActorType               string
	ActorID                 string
	DisplayName             string
	PrincipalType           string
	PrincipalID             string
	AuthMethod              string
	SessionID               *string
	MachineTokenID          *string
	MixedCredentialsPresent bool
	BearerTokenPresent      bool
	SessionCookiePresent    bool
}

func EnsureActorPermission(
	ctx context.Context,
	conn *sql.DB,
	actor AuthenticatedActor,
	request PermissionRequest,
) (AuthenticatedActor, error) {
	request.PrincipalType = actor.PrincipalType
	request.PrincipalID = actor.PrincipalID

	requestedCheck, err := CheckPermission(ctx, conn, request)
	if err != nil {
		return AuthenticatedActor{}, err
	}
	if requestedCheck.Allowed {
		return actor, nil
	}
	if requestedCheck.Denied {
		return AuthenticatedActor{}, ErrForbidden
	}

	adminCheck, err := CheckPermission(ctx, conn, PermissionRequest{
		PrincipalType: actor.PrincipalType,
		PrincipalID:   actor.PrincipalID,
		Permission:    AdminPermission,
	})
	if err != nil {
		return AuthenticatedActor{}, err
	}
	if adminCheck.Allowed {
		return actor, nil
	}
	return AuthenticatedActor{}, ErrForbidden
}

func ActorHasPermission(
	ctx context.Context,
	conn *sql.DB,
	actor AuthenticatedActor,
	request PermissionRequest,
) (bool, error) {
	_, err := EnsureActorPermission(ctx, conn, actor, request)
	if errors.Is(err, ErrForbidden) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
