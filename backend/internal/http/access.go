package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
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

var protectedAccessGroups = map[string]struct {
	DisplayName string
	Permissions []string
}{
	"administrators": {
		DisplayName: "Administrators",
	},
	"users": {
		DisplayName: "Users",
		Permissions: []string{
			"finding:comment",
			"finding:status_change:request",
			"finding:view",
			"project:view",
			"report:view",
		},
	},
	"security-reviewers": {
		DisplayName: "Security Reviewers",
		Permissions: []string{
			"finding:comment",
			"finding:status_change:approve",
			"finding:status_change:request",
			"finding:view",
			"import:history:view",
			"project:view",
			"report:view",
		},
	},
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

type accessGroupCreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type accessMembershipCreateRequest struct {
	GroupID       string `json:"group_id"`
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
}

type accessPermissionAssignRequest struct {
	PrincipalType string  `json:"principal_type"`
	PrincipalID   string  `json:"principal_id"`
	Permission    string  `json:"permission"`
	Effect        string  `json:"effect"`
	ScopeType     *string `json:"scope_type"`
	ScopeID       *string `json:"scope_id"`
}

type accessUserCreateRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type accessUserPasswordSetRequest struct {
	NewPassword string `json:"new_password"`
}

func mountAccessRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/admin/access", func(w http.ResponseWriter, r *http.Request) {
		listAccessManagement(w, r, settings, deps)
	})
	router.Post("/api/admin/access/groups", func(w http.ResponseWriter, r *http.Request) {
		createAccessGroup(w, r, settings, deps)
	})
	router.Post("/api/admin/access/memberships", func(w http.ResponseWriter, r *http.Request) {
		createAccessMembership(w, r, settings, deps)
	})
	router.Post("/api/admin/access/permissions", func(w http.ResponseWriter, r *http.Request) {
		assignAccessPermission(w, r, settings, deps)
	})
	router.Post("/api/admin/access/users", func(w http.ResponseWriter, r *http.Request) {
		createAccessUser(w, r, settings, deps)
	})
	router.Patch("/api/admin/access/users/{userID}/password", func(w http.ResponseWriter, r *http.Request) {
		setAccessUserPassword(w, r, settings, deps)
	})
}

func listAccessManagement(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"}); !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	if err := ensureProtectedAccessGroups(r, queries); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
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

func ensureProtectedAccessGroups(r *http.Request, queries *dbgen.Queries) error {
	for name, definition := range protectedAccessGroups {
		group, err := queries.GetGroupByName(r.Context(), name)
		if errors.Is(err, sql.ErrNoRows) {
			now := time.Now().UTC()
			group, err = queries.CreateGroup(r.Context(), dbgen.CreateGroupParams{
				ID:          uuid.NewString(),
				Name:        name,
				DisplayName: definition.DisplayName,
				IsProtected: true,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		if err != nil {
			return err
		}
		for _, permission := range definition.Permissions {
			if err := ensureAccessPermissionAssignment(r, queries, group.ID, permission); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureAccessPermissionAssignment(r *http.Request, queries *dbgen.Queries, groupID string, permission string) error {
	scopeType := sql.NullString{}
	scopeID := sql.NullString{}
	_, err := queries.GetPermissionAssignment(r.Context(), dbgen.GetPermissionAssignmentParams{
		PrincipalType: identity.PrincipalTypeGroup,
		PrincipalID:   groupID,
		Permission:    permission,
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     scopeType,
		ScopeID:       scopeID,
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := time.Now().UTC()
	_, err = queries.CreatePermissionAssignment(r.Context(), dbgen.CreatePermissionAssignmentParams{
		ID:            uuid.NewString(),
		PrincipalType: identity.PrincipalTypeGroup,
		PrincipalID:   groupID,
		Permission:    permission,
		Effect:        identity.PermissionEffectAllow,
		ScopeType:     scopeType,
		ScopeID:       scopeID,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	return err
}

func createAccessGroup(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"})
	if !ok {
		return
	}
	var payload accessGroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid group request")
		return
	}
	queries := dbgen.New(deps.DB)
	if _, err := queries.GetGroupByName(r.Context(), payload.Name); err == nil {
		writeError(w, http.StatusConflict, "Group name already exists")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	now := time.Now().UTC()
	group, err := queries.CreateGroup(r.Context(), dbgen.CreateGroupParams{
		ID:          uuid.NewString(),
		Name:        payload.Name,
		DisplayName: payload.DisplayName,
		IsProtected: false,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Group name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "access.group.create",
		TargetType: stringPtr("group"),
		TargetID:   stringPtr(group.ID),
		Metadata: map[string]any{
			"name":         group.Name,
			"display_name": group.DisplayName,
			"is_protected": group.IsProtected,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, accessGroupFromDB(group))
}

func createAccessMembership(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"})
	if !ok {
		return
	}
	var payload accessMembershipCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid membership request")
		return
	}
	queries := dbgen.New(deps.DB)
	if _, err := queries.GetGroup(r.Context(), payload.GroupID); errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Group not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !principalExists(r, queries, payload.PrincipalType, payload.PrincipalID) {
		writeError(w, http.StatusNotFound, "Principal not found")
		return
	}
	membership, err := queries.GetGroupMembership(r.Context(), dbgen.GetGroupMembershipParams{
		GroupID:       payload.GroupID,
		PrincipalType: payload.PrincipalType,
		PrincipalID:   payload.PrincipalID,
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, accessMembershipFromDB(membership))
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	now := time.Now().UTC()
	membership, err = queries.CreateGroupMembership(r.Context(), dbgen.CreateGroupMembershipParams{
		ID:            uuid.NewString(),
		GroupID:       payload.GroupID,
		PrincipalType: payload.PrincipalType,
		PrincipalID:   payload.PrincipalID,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "access.membership.add",
		TargetType: stringPtr("group_membership"),
		TargetID:   stringPtr(membership.ID),
		Metadata: map[string]any{
			"group_id":       membership.GroupID,
			"principal_type": membership.PrincipalType,
			"principal_id":   membership.PrincipalID,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, accessMembershipFromDB(membership))
}

func assignAccessPermission(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"})
	if !ok {
		return
	}
	var payload accessPermissionAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid permission assignment request")
		return
	}
	if (payload.ScopeType == nil) != (payload.ScopeID == nil) {
		writeError(w, http.StatusBadRequest, "Invalid permission assignment request")
		return
	}
	queries := dbgen.New(deps.DB)
	if !principalExists(r, queries, payload.PrincipalType, payload.PrincipalID) {
		writeError(w, http.StatusNotFound, "Principal not found")
		return
	}
	scopeType := nullStringFromPtr(payload.ScopeType)
	scopeID := nullStringFromPtr(payload.ScopeID)
	assignment, err := queries.GetPermissionAssignment(r.Context(), dbgen.GetPermissionAssignmentParams{
		PrincipalType: payload.PrincipalType,
		PrincipalID:   payload.PrincipalID,
		Permission:    payload.Permission,
		Effect:        payload.Effect,
		ScopeType:     scopeType,
		ScopeID:       scopeID,
	})
	if err == nil {
		writeJSON(w, http.StatusCreated, accessPermissionAssignmentFromDB(assignment))
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	now := time.Now().UTC()
	assignment, err = queries.CreatePermissionAssignment(r.Context(), dbgen.CreatePermissionAssignmentParams{
		ID:            uuid.NewString(),
		PrincipalType: payload.PrincipalType,
		PrincipalID:   payload.PrincipalID,
		Permission:    payload.Permission,
		Effect:        payload.Effect,
		ScopeType:     scopeType,
		ScopeID:       scopeID,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "access.permission.assign",
		TargetType: stringPtr("permission_assignment"),
		TargetID:   stringPtr(assignment.ID),
		Metadata: map[string]any{
			"principal_type": assignment.PrincipalType,
			"principal_id":   assignment.PrincipalID,
			"permission":     assignment.Permission,
			"effect":         assignment.Effect,
			"scope_type":     payload.ScopeType,
			"scope_id":       payload.ScopeID,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, accessPermissionAssignmentFromDB(assignment))
}

func createAccessUser(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"})
	if !ok {
		return
	}
	if !settings.LocalAuthEnabled {
		writeError(w, http.StatusForbidden, "Local authentication is disabled")
		return
	}
	var payload accessUserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid user account request")
		return
	}
	user, err := identity.CreateUser(r.Context(), deps.DB, payload.Username, payload.DisplayName, payload.Password, time.Now().UTC())
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Username already exists")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "Invalid user account request")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "access.user.create",
		TargetType: stringPtr("user"),
		TargetID:   stringPtr(user.ID),
		Metadata: map[string]any{
			"username":     user.Username,
			"display_name": user.DisplayName,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, accessUserFromDB(user))
}

func setAccessUserPassword(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "access:manage"})
	if !ok {
		return
	}
	if !settings.LocalAuthEnabled {
		writeError(w, http.StatusForbidden, "Local authentication is disabled")
		return
	}
	var payload accessUserPasswordSetRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid new password")
		return
	}
	queries := dbgen.New(deps.DB)
	userID := chi.URLParam(r, "userID")
	user, err := queries.GetUser(r.Context(), userID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "User not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := identity.SetUserPassword(r.Context(), deps.DB, userID, payload.NewPassword, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid new password")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "access.user.password.set",
		TargetType: stringPtr("user"),
		TargetID:   stringPtr(user.ID),
		Metadata:   map[string]any{"username": user.Username},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func principalExists(r *http.Request, queries *dbgen.Queries, principalType string, principalID string) bool {
	switch principalType {
	case identity.PrincipalTypeUser:
		_, err := queries.GetUser(r.Context(), principalID)
		return err == nil
	case identity.PrincipalTypeGroup:
		_, err := queries.GetGroup(r.Context(), principalID)
		return err == nil
	case identity.PrincipalTypeMachine:
		_, err := queries.GetMachineCredential(r.Context(), principalID)
		return err == nil
	default:
		return false
	}
}

func accessUsersFromDB(users []dbgen.User) []accessUserResponse {
	responses := make([]accessUserResponse, 0, len(users))
	for _, user := range users {
		responses = append(responses, accessUserFromDB(user))
	}
	return responses
}

func accessUserFromDB(user dbgen.User) accessUserResponse {
	return accessUserResponse{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		IsActive:    user.IsActive,
		CreatedAt:   user.CreatedAt.UTC(),
		UpdatedAt:   user.UpdatedAt.UTC(),
	}
}

func accessGroupFromDB(group dbgen.Group) accessGroupResponse {
	return accessGroupResponse{
		ID:          group.ID,
		Name:        group.Name,
		DisplayName: group.DisplayName,
		IsProtected: group.IsProtected,
		CreatedAt:   group.CreatedAt.UTC(),
		UpdatedAt:   group.UpdatedAt.UTC(),
	}
}

func accessMembershipFromDB(membership dbgen.GroupMembership) accessMembershipResponse {
	return accessMembershipResponse{
		ID:            membership.ID,
		GroupID:       membership.GroupID,
		PrincipalType: membership.PrincipalType,
		PrincipalID:   membership.PrincipalID,
		CreatedAt:     membership.CreatedAt.UTC(),
		UpdatedAt:     membership.UpdatedAt.UTC(),
	}
}

func accessPermissionAssignmentFromDB(assignment dbgen.PermissionAssignment) accessPermissionAssignmentResponse {
	return accessPermissionAssignmentResponse{
		ID:            assignment.ID,
		PrincipalType: assignment.PrincipalType,
		PrincipalID:   assignment.PrincipalID,
		Permission:    assignment.Permission,
		Effect:        assignment.Effect,
		ScopeType:     optionalStringFromNull(assignment.ScopeType),
		ScopeID:       optionalStringFromNull(assignment.ScopeID),
		CreatedAt:     assignment.CreatedAt.UTC(),
		UpdatedAt:     assignment.UpdatedAt.UTC(),
	}
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
		responses = append(responses, accessGroupFromDB(group))
	}
	return responses
}

func accessMembershipsFromDB(memberships []dbgen.GroupMembership) []accessMembershipResponse {
	responses := make([]accessMembershipResponse, 0, len(memberships))
	for _, membership := range memberships {
		responses = append(responses, accessMembershipFromDB(membership))
	}
	return responses
}

func accessPermissionAssignmentsFromDB(assignments []dbgen.PermissionAssignment) []accessPermissionAssignmentResponse {
	responses := make([]accessPermissionAssignmentResponse, 0, len(assignments))
	for _, assignment := range assignments {
		responses = append(responses, accessPermissionAssignmentFromDB(assignment))
	}
	return responses
}
