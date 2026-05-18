package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
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

func ActorHasAnyScopedPermission(
	ctx context.Context,
	conn *sql.DB,
	actor AuthenticatedActor,
	permission string,
	scopeType string,
) (bool, error) {
	unscoped, err := CheckPermission(ctx, conn, PermissionRequest{
		PrincipalType: actor.PrincipalType,
		PrincipalID:   actor.PrincipalID,
		Permission:    permission,
	})
	if err != nil {
		return false, err
	}
	if unscoped.Denied {
		return false, nil
	}
	if unscoped.Allowed {
		return true, nil
	}

	admin, err := CheckPermission(ctx, conn, PermissionRequest{
		PrincipalType: actor.PrincipalType,
		PrincipalID:   actor.PrincipalID,
		Permission:    AdminPermission,
	})
	if err != nil {
		return false, err
	}
	if admin.Allowed {
		return true, nil
	}

	queries := dbgen.New(conn)
	refs, err := principalRefsForCheck(ctx, queries, actor.PrincipalType, actor.PrincipalID)
	if err != nil {
		return false, err
	}
	assignments, err := scopedAssignments(ctx, queries, refs, permission, scopeType)
	if err != nil {
		return false, err
	}
	deniedScopes := map[string]bool{}
	for _, assignment := range assignments {
		if assignment.Effect == PermissionEffectDeny && assignment.ScopeID.Valid {
			deniedScopes[assignment.ScopeID.String] = true
		}
	}
	for _, assignment := range assignments {
		if assignment.Effect == PermissionEffectAllow &&
			assignment.ScopeID.Valid &&
			!deniedScopes[assignment.ScopeID.String] {
			return true, nil
		}
	}
	return false, nil
}
