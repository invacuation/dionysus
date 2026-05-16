package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

func TestAccessListReturnsSafeAccessManagementData(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	insertHTTPPermission(t, conn, httpPermissionFixture{
		ID:            "permission-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "access:manage",
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	insertHTTPGroup(t, conn, httpGroupFixture{
		ID:          "group-1",
		Name:        "operators",
		DisplayName: "Operators",
		CreatedAt:   now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
	})
	insertHTTPMembership(t, conn, httpMembershipFixture{
		ID:            "membership-1",
		GroupID:       "group-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/access", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body accessListResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Users) != 1 || body.Users[0].Username != "alice" {
		t.Fatalf("users = %#v, want alice", body.Users)
	}
	groupNames := map[string]bool{}
	for _, group := range body.Groups {
		groupNames[group.Name] = true
	}
	for _, name := range []string{"administrators", "operators", "security-reviewers", "users"} {
		if !groupNames[name] {
			t.Fatalf("groups = %#v, want %s", body.Groups, name)
		}
	}
	if len(body.Memberships) != 1 || body.Memberships[0].GroupID != "group-1" {
		t.Fatalf("memberships = %#v, want group-1 membership", body.Memberships)
	}
	hasAccessManage := false
	for _, assignment := range body.PermissionAssignments {
		if assignment.Permission == "access:manage" {
			hasAccessManage = true
		}
	}
	if !hasAccessManage {
		t.Fatalf("permission assignments = %#v, want access:manage", body.PermissionAssignments)
	}
	if len(body.AvailablePermissions) == 0 {
		t.Fatal("available permissions is empty")
	}
}

func TestAccessCreateGroupAndRejectDuplicate(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/access/groups",
		strings.NewReader(`{"name":"reviewers","display_name":"Reviewers"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		createRequest.AddCookie(cookie)
	}
	router.ServeHTTP(createResponse, createRequest)

	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", createResponse.Code, http.StatusCreated, createResponse.Body.String())
	}
	var created accessGroupResponse
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Name != "reviewers" || created.DisplayName != "Reviewers" || created.IsProtected {
		t.Fatalf("created group = %#v, want reviewers non-protected", created)
	}

	duplicateResponse := httptest.NewRecorder()
	duplicateRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/access/groups",
		strings.NewReader(`{"name":"reviewers","display_name":"Duplicate Reviewers"}`),
	)
	duplicateRequest.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		duplicateRequest.AddCookie(cookie)
	}
	router.ServeHTTP(duplicateResponse, duplicateRequest)

	if duplicateResponse.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", duplicateResponse.Code, http.StatusConflict)
	}
	assertJSONDetail(t, duplicateResponse, "Group name already exists")
}

func TestAccessCreateMembershipForMachineCredential(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)
	now := time.Now().UTC()
	insertHTTPGroup(t, conn, httpGroupFixture{
		ID:          "group-1",
		Name:        "automation",
		DisplayName: "Automation",
		CreatedAt:   now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
	})
	insertHTTPMachineCredential(t, conn, httpMachineCredentialFixture{
		ID:                 "machine-1",
		Name:               "ci-runner",
		ClientID:           "client-1",
		ClientSecretDigest: "digest",
		IsActive:           true,
		CreatedAt:          now.Add(-time.Hour),
		UpdatedAt:          now.Add(-time.Hour),
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/access/memberships",
		strings.NewReader(`{"group_id":"group-1","principal_type":"machine","principal_id":"machine-1"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var body accessMembershipResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.GroupID != "group-1" || body.PrincipalType != identity.PrincipalTypeMachine || body.PrincipalID != "machine-1" {
		t.Fatalf("membership = %#v, want machine-1 in group-1", body)
	}
}

func TestAccessAssignsScopedAllowAndDenyPermissions(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)

	allowResponse := postAccessPermission(t, router, loginResponse, `{"principal_type":"user","principal_id":"user-1","permission":"finding:view","effect":"allow","scope_type":"project","scope_id":"project-1"}`)
	if allowResponse.Code != http.StatusCreated {
		t.Fatalf("allow status = %d, want %d; body = %s", allowResponse.Code, http.StatusCreated, allowResponse.Body.String())
	}
	var allow accessPermissionAssignmentResponse
	if err := json.NewDecoder(allowResponse.Body).Decode(&allow); err != nil {
		t.Fatalf("decode allow response: %v", err)
	}
	if allow.Effect != identity.PermissionEffectAllow || allow.ScopeType == nil || *allow.ScopeType != "project" {
		t.Fatalf("allow assignment = %#v, want scoped allow", allow)
	}

	denyResponse := postAccessPermission(t, router, loginResponse, `{"principal_type":"user","principal_id":"user-1","permission":"finding:view","effect":"deny","scope_type":"project","scope_id":"project-1"}`)
	if denyResponse.Code != http.StatusCreated {
		t.Fatalf("deny status = %d, want %d; body = %s", denyResponse.Code, http.StatusCreated, denyResponse.Body.String())
	}
	var deny accessPermissionAssignmentResponse
	if err := json.NewDecoder(denyResponse.Body).Decode(&deny); err != nil {
		t.Fatalf("decode deny response: %v", err)
	}
	if deny.Effect != identity.PermissionEffectDeny || deny.ScopeID == nil || *deny.ScopeID != "project-1" {
		t.Fatalf("deny assignment = %#v, want scoped deny", deny)
	}
}

func TestAccessAssignPermissionRejectsHalfScope(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)

	response := postAccessPermission(t, router, loginResponse, `{"principal_type":"user","principal_id":"user-1","permission":"finding:view","effect":"allow","scope_type":"project"}`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	assertJSONDetail(t, response, "Invalid permission assignment request")
}

func TestAccessAdminCreatesLocalUser(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/access/users",
		strings.NewReader(`{"username":"bob","display_name":"Bob Builder","password":"new correct horse battery"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusCreated, response.Body.String())
	}
	var body accessUserResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Username != "bob" || body.DisplayName != "Bob Builder" || !body.IsActive {
		t.Fatalf("created user = %#v, want active bob", body)
	}
	bobLogin := loginNamedHTTPUser(t, router, "bob", "new correct horse battery")
	if bobLogin.Code != http.StatusOK {
		t.Fatalf("bob login status = %d, want %d; body = %s", bobLogin.Code, http.StatusOK, bobLogin.Body.String())
	}
}

func TestAccessAdminCreateUserDisabledWhenLocalAuthDisabled(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	loginRouter, loginResponse := newAccessAdminTestRouter(t, conn)
	_ = loginRouter
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              false,
	}, WithDB(conn))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/access/users",
		strings.NewReader(`{"username":"bob","display_name":"Bob Builder","password":"new correct horse battery"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	assertJSONDetail(t, response, "Local authentication is disabled")
}

func TestAccessAdminChangesUserPassword(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	router, loginResponse := newAccessAdminTestRouter(t, conn)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-2",
		Username:     "bob",
		DisplayName:  "Bob Builder",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPatch,
		"/api/admin/access/users/user-2/password",
		strings.NewReader(`{"new_password":"new correct horse battery"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusNoContent, response.Body.String())
	}
	oldLogin := loginNamedHTTPUser(t, router, "bob", "correct horse battery staple")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password login status = %d, want %d", oldLogin.Code, http.StatusUnauthorized)
	}
	newLogin := loginNamedHTTPUser(t, router, "bob", "new correct horse battery")
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password login status = %d, want %d; body = %s", newLogin.Code, http.StatusOK, newLogin.Body.String())
	}
}

func newAccessAdminTestRouter(t *testing.T, conn httpDB) (http.Handler, *httptest.ResponseRecorder) {
	t.Helper()
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	insertHTTPPermission(t, conn, httpPermissionFixture{
		ID:            "permission-1",
		PrincipalType: identity.PrincipalTypeUser,
		PrincipalID:   "user-1",
		Permission:    "access:manage",
		Effect:        identity.PermissionEffectAllow,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")
	return router, loginResponse
}

func postAccessPermission(t *testing.T, router http.Handler, loginResponse *httptest.ResponseRecorder, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/access/permissions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)
	return response
}

func TestAccessListRequiresAccessManage(t *testing.T) {
	conn := openSessionHTTPTestDB(t)
	now := time.Now().UTC()
	insertHTTPUser(t, conn, httpUserFixture{
		ID:           "user-1",
		Username:     "alice",
		DisplayName:  "Alice",
		IsActive:     true,
		PasswordHash: pythonArgon2PasswordHash,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	})
	router := NewRouter(config.Settings{
		SessionIdleTimeoutMinutes:     30,
		SessionAbsoluteTimeoutMinutes: 480,
		LocalAuthEnabled:              true,
	}, WithDB(conn))
	loginResponse := loginHTTPUser(t, router, "correct horse battery staple")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/access", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		request.AddCookie(cookie)
	}
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	assertJSONDetail(t, response, "Forbidden")
}
