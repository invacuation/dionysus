package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

var knownPermissions = []string{
	"access:manage",
	"admin:*",
	"asset:create",
	"asset:delete",
	"asset:update",
	"credential:manage",
	"finding:comment",
	"finding:status_change:approve",
	"finding:status_change:request",
	"finding:view",
	"import:history:view",
	"import:upload",
	"project:create",
	"project:delete",
	"project:update",
	"project:view",
	"report:view",
}

type accessListResponse struct {
	Users                 []accessUserResponse                 `json:"users"`
	MachineCredentials    []accessMachineCredentialResponse    `json:"machine_credentials"`
	Groups                []accessGroupResponse                `json:"groups"`
	Memberships           []accessMembershipResponse           `json:"memberships"`
	PermissionAssignments []accessPermissionAssignmentResponse `json:"permission_assignments"`
	AvailablePermissions  []string                             `json:"available_permissions"`
}

type accessUserResponse struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accessMachineCredentialResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	ClientID  string     `json:"client_id"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type accessGroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	IsProtected bool      `json:"is_protected"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accessMembershipResponse struct {
	ID            string    `json:"id"`
	GroupID       string    `json:"group_id"`
	PrincipalType string    `json:"principal_type"`
	PrincipalID   string    `json:"principal_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type accessPermissionAssignmentResponse struct {
	ID            string    `json:"id"`
	PrincipalType string    `json:"principal_type"`
	PrincipalID   string    `json:"principal_id"`
	Permission    string    `json:"permission"`
	Effect        string    `json:"effect"`
	ScopeType     *string   `json:"scope_type"`
	ScopeID       *string   `json:"scope_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func mountAccessRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/admin/access", func(w http.ResponseWriter, r *http.Request) {
		listAccessManagement(w, r, settings, deps)
	})
}

func listAccessManagement(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"}); !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	users, err := queries.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	credentials, err := queries.ListMachineCredentials(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	groups, err := queries.ListGroups(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	memberships, err := queries.ListGroupMemberships(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	assignments, err := queries.ListPermissionAssignments(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	writeJSON(w, http.StatusOK, accessListResponse{
		Users:                 accessUsersFromDB(users),
		MachineCredentials:    accessMachineCredentialsFromDB(credentials),
		Groups:                accessGroupsFromDB(groups),
		Memberships:           accessMembershipsFromDB(memberships),
		PermissionAssignments: accessPermissionAssignmentsFromDB(assignments),
		AvailablePermissions:  knownPermissions,
	})
}

func accessUsersFromDB(users []dbgen.User) []accessUserResponse {
	responses := make([]accessUserResponse, 0, len(users))
	for _, user := range users {
		responses = append(responses, accessUserResponse{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			IsActive:    user.IsActive,
			CreatedAt:   user.CreatedAt.UTC(),
			UpdatedAt:   user.UpdatedAt.UTC(),
		})
	}
	return responses
}

func accessMachineCredentialsFromDB(credentials []dbgen.MachineCredential) []accessMachineCredentialResponse {
	responses := make([]accessMachineCredentialResponse, 0, len(credentials))
	for _, credential := range credentials {
		var revokedAt *time.Time
		if credential.RevokedAt.Valid {
			value := credential.RevokedAt.Time.UTC()
			revokedAt = &value
		}
		responses = append(responses, accessMachineCredentialResponse{
			ID:        credential.ID,
			Name:      credential.Name,
			ClientID:  credential.ClientID,
			IsActive:  credential.IsActive,
			CreatedAt: credential.CreatedAt.UTC(),
			UpdatedAt: credential.UpdatedAt.UTC(),
			RevokedAt: revokedAt,
		})
	}
	return responses
}

func accessGroupsFromDB(groups []dbgen.Group) []accessGroupResponse {
	responses := make([]accessGroupResponse, 0, len(groups))
	for _, group := range groups {
		responses = append(responses, accessGroupResponse{
			ID:          group.ID,
			Name:        group.Name,
			DisplayName: group.DisplayName,
			IsProtected: group.IsProtected,
			CreatedAt:   group.CreatedAt.UTC(),
			UpdatedAt:   group.UpdatedAt.UTC(),
		})
	}
	return responses
}

func accessMembershipsFromDB(memberships []dbgen.GroupMembership) []accessMembershipResponse {
	responses := make([]accessMembershipResponse, 0, len(memberships))
	for _, membership := range memberships {
		responses = append(responses, accessMembershipResponse{
			ID:            membership.ID,
			GroupID:       membership.GroupID,
			PrincipalType: membership.PrincipalType,
			PrincipalID:   membership.PrincipalID,
			CreatedAt:     membership.CreatedAt.UTC(),
			UpdatedAt:     membership.UpdatedAt.UTC(),
		})
	}
	return responses
}

func accessPermissionAssignmentsFromDB(assignments []dbgen.PermissionAssignment) []accessPermissionAssignmentResponse {
	responses := make([]accessPermissionAssignmentResponse, 0, len(assignments))
	for _, assignment := range assignments {
		responses = append(responses, accessPermissionAssignmentResponse{
			ID:            assignment.ID,
			PrincipalType: assignment.PrincipalType,
			PrincipalID:   assignment.PrincipalID,
			Permission:    assignment.Permission,
			Effect:        assignment.Effect,
			ScopeType:     optionalStringFromNull(assignment.ScopeType),
			ScopeID:       optionalStringFromNull(assignment.ScopeID),
			CreatedAt:     assignment.CreatedAt.UTC(),
			UpdatedAt:     assignment.UpdatedAt.UTC(),
		})
	}
	return responses
}
