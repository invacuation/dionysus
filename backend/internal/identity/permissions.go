package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

const (
	PrincipalTypeUser    = "user"
	PrincipalTypeGroup   = "group"
	PrincipalTypeMachine = "machine"

	PermissionEffectAllow = "allow"
	PermissionEffectDeny  = "deny"
)

type PermissionRequest struct {
	PrincipalType string
	PrincipalID   string
	Permission    string
	ScopeType     *string
	ScopeID       *string
}

type PermissionCheck struct {
	Allowed     bool
	Explanation string
	Denied      bool
}

type principalRef struct {
	typ string
	id  string
}

func CheckPermission(ctx context.Context, conn *sql.DB, request PermissionRequest) (PermissionCheck, error) {
	if err := validateScopePair(request.ScopeType, request.ScopeID); err != nil {
		return PermissionCheck{}, err
	}

	queries := dbgen.New(conn)
	refs, err := principalRefsForCheck(ctx, queries, request.PrincipalType, request.PrincipalID)
	if err != nil {
		return PermissionCheck{}, err
	}

	assignments, err := matchingAssignments(ctx, queries, request, refs)
	if err != nil {
		return PermissionCheck{}, err
	}
	groupIDs := groupIDsFromRefs(refs)

	denies := filterAssignments(assignments, PermissionEffectDeny)
	if len(denies) > 0 {
		explanation, err := denyExplanation(ctx, queries, denies, groupIDs)
		if err != nil {
			return PermissionCheck{}, err
		}
		return PermissionCheck{Allowed: false, Explanation: explanation, Denied: true}, nil
	}

	for _, assignment := range assignments {
		if assignment.Effect == PermissionEffectAllow &&
			assignment.PrincipalType == request.PrincipalType &&
			assignment.PrincipalID == request.PrincipalID {
			return PermissionCheck{
				Allowed:     true,
				Explanation: fmt.Sprintf("direct allow matched %s on %s:%s", request.Permission, scopeValue(request.ScopeType), scopeValue(request.ScopeID)),
			}, nil
		}
	}

	allows := filterAssignments(assignments, PermissionEffectAllow)
	if len(allows) > 0 {
		groupIDs := make([]string, 0, len(allows))
		for _, assignment := range allows {
			if assignment.PrincipalType == PrincipalTypeGroup {
				groupIDs = append(groupIDs, assignment.PrincipalID)
			}
		}
		names, err := groupNames(ctx, queries, groupIDs)
		if err != nil {
			return PermissionCheck{}, err
		}
		return PermissionCheck{
			Allowed: true,
			Explanation: fmt.Sprintf(
				"group allow matched %s on %s:%s via %s",
				request.Permission,
				scopeValue(request.ScopeType),
				scopeValue(request.ScopeID),
				formatNames(names),
			),
		}, nil
	}

	names, err := groupNames(ctx, queries, groupIDs)
	if err != nil {
		return PermissionCheck{}, err
	}
	return PermissionCheck{
		Allowed: false,
		Explanation: fmt.Sprintf(
			"no matching grant for %s on %s:%s; group context: %s",
			request.Permission,
			scopeValue(request.ScopeType),
			scopeValue(request.ScopeID),
			formatNames(names),
		),
	}, nil
}

func principalRefsForCheck(ctx context.Context, queries *dbgen.Queries, principalType string, principalID string) ([]principalRef, error) {
	refs := []principalRef{{typ: principalType, id: principalID}}
	pending := []principalRef{{typ: principalType, id: principalID}}
	seenGroups := map[string]bool{}

	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		groupIDs, err := queries.ListGroupIDsForPrincipal(ctx, dbgen.ListGroupIDsForPrincipalParams{
			PrincipalType: current.typ,
			PrincipalID:   current.id,
		})
		if err != nil {
			return nil, err
		}
		for _, groupID := range groupIDs {
			if seenGroups[groupID] {
				continue
			}
			seenGroups[groupID] = true
			groupRef := principalRef{typ: PrincipalTypeGroup, id: groupID}
			refs = append(refs, groupRef)
			pending = append(pending, groupRef)
		}
	}
	return refs, nil
}

func matchingAssignments(
	ctx context.Context,
	queries *dbgen.Queries,
	request PermissionRequest,
	refs []principalRef,
) ([]dbgen.PermissionAssignment, error) {
	scopeType := nullStringFromPtr(request.ScopeType)
	scopeID := nullStringFromPtr(request.ScopeID)
	var assignments []dbgen.PermissionAssignment
	for _, ref := range refs {
		matches, err := queries.ListMatchingAssignmentsForPrincipal(ctx, dbgen.ListMatchingAssignmentsForPrincipalParams{
			PrincipalType: ref.typ,
			PrincipalID:   ref.id,
			Permission:    request.Permission,
			ScopeType:     scopeType,
			ScopeID:       scopeID,
		})
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, matches...)
	}
	return assignments, nil
}

func validateScopePair(scopeType *string, scopeID *string) error {
	if (scopeType == nil) != (scopeID == nil) {
		return errors.New("scope_type and scope_id must both be set or both be nil")
	}
	return nil
}

func filterAssignments(assignments []dbgen.PermissionAssignment, effect string) []dbgen.PermissionAssignment {
	filtered := make([]dbgen.PermissionAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment.Effect == effect {
			filtered = append(filtered, assignment)
		}
	}
	return filtered
}

func groupIDsFromRefs(refs []principalRef) []string {
	groupIDs := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.typ == PrincipalTypeGroup {
			groupIDs = append(groupIDs, ref.id)
		}
	}
	return groupIDs
}

func denyExplanation(
	ctx context.Context,
	queries *dbgen.Queries,
	denies []dbgen.PermissionAssignment,
	groupIDs []string,
) (string, error) {
	denySources := make([]string, 0, len(denies))
	for _, assignment := range denies {
		if assignment.PrincipalType == PrincipalTypeGroup {
			names, err := groupNames(ctx, queries, []string{assignment.PrincipalID})
			if err != nil {
				return "", err
			}
			denySources = append(denySources, names...)
		} else {
			denySources = append(denySources, fmt.Sprintf("%s:%s", assignment.PrincipalType, assignment.PrincipalID))
		}
	}
	contextNames, err := groupNames(ctx, queries, groupIDs)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"explicit deny matched from %s; group context: %s",
		formatNames(denySources),
		formatNames(contextNames),
	), nil
}

func groupNames(ctx context.Context, queries *dbgen.Queries, groupIDs []string) ([]string, error) {
	names := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		name, err := queries.GetGroupName(ctx, groupID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func formatNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return strings.Join(unique, ", ")
}

func nullStringFromPtr(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func scopeValue(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}
