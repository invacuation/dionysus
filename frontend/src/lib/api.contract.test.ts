import {
  approveFindingStatusRequest,
  assignAccessPermission,
  changeCurrentUserPassword,
  createAccessGroup,
  createAccessMembership,
  createFindingComment,
  createMachineCredential,
  createFolder,
  createProject,
  createScanTarget,
  getSecuritySettings,
  listAccessManagement,
  listAdminImportHistory,
  listAuditLog,
  listFindings,
  listMachineCredentials,
  listUserSessions,
  regenerateMachineCredentialSecret,
  rejectFindingStatusRequest,
  revokeMachineCredential,
  revokeUserSession,
  setAccessUserPassword,
  testPermission,
  updateAsset,
  updateFindingStatus,
  updateProject,
  updateSecuritySettings,
  type AccessGroup,
  type AccessListResponse,
  type AccessMembership,
  type AccessPermissionAssignment,
  type ActorMetadata,
  type AdminImportAttempt,
  type AdminImportHistoryResponse,
  type Asset,
  type AuditLogEntry,
  type AuditLogResponse,
  type FindingComment,
  type FindingDetail,
  type FindingStatusChangeRequest,
  type MachineCredential,
  type MachineCredentialsResponse,
  type MachineCredentialWithSecret,
  type PermissionTestResponse,
  type Project,
  type SecuritySettings,
  type UserSession,
  type UserSessionsResponse,
} from "./api"
import {
  formatAuditMetadataForDisplay,
  importUploaderLabel,
} from "../features/admin/admin-page"

globalThis.fetch = async () =>
  new Response("{}", {
    headers: { "content-type": "application/json" },
    status: 200,
  })

const detail = {
  comments: [],
  status_change_requests: [],
} as unknown as FindingDetail

const auditEntry: AuditLogEntry = {
  id: "audit-1",
  event_type: "finding.status.changed",
  actor_principal_type: "user",
  actor_principal_id: "alice-id",
  actor_display: "Alice",
  target_type: "finding",
  target_id: "finding-1",
  project_id: "project-1",
  ip_address: "127.0.0.1",
  user_agent: "test-agent",
  metadata: { status_to: "fixed" },
  created_at: "2026-05-08T12:00:00Z",
}
const auditLog = listAuditLog({
  event_type: "finding.status.changed",
  project_id: "project-1",
  target_type: "finding",
  target_id: "finding-1",
  limit: 25,
})
const filteredFindings = listFindings({
  fix_available: true,
  present_in_latest_scan: true,
  sort: "last_seen",
  direction: "desc",
})
const auditLogResponse: AuditLogResponse = {
  events: [auditEntry],
  event_types: ["finding.status.changed"],
}
const findingAuditMetadata = formatAuditMetadataForDisplay(
  {
    actor_principal_id: "alice-id",
    target_id: "finding-1",
    project_id: "project-1",
    comment_id: "comment-1",
  },
  "finding",
)
const machineCredential: MachineCredential = {
  id: "credential-1",
  name: "ci-runner",
  client_id: "mc_123",
  is_active: true,
  created_by_principal_type: "user",
  created_by_principal_id: "user-1",
  created_by_display: "Alice",
  created_at: "2026-05-08T12:00:00Z",
  updated_at: "2026-05-08T12:00:00Z",
  revoked_at: null,
}
const machineCredentialWithSecret: MachineCredentialWithSecret = {
  ...machineCredential,
  client_secret: "secret-value",
}
const machineCredentials: Promise<MachineCredentialsResponse> = listMachineCredentials()
const createdMachineCredential: Promise<MachineCredentialWithSecret> = createMachineCredential({
  name: "ci-runner",
})
const regeneratedMachineCredentialSecret: Promise<MachineCredentialWithSecret> =
  regenerateMachineCredentialSecret("credential-1", {
    revoke_tokens: true,
  })
const revokedMachineCredential: Promise<MachineCredential> = revokeMachineCredential("credential-1", {
  revoke_tokens: true,
})
const permissionTest: Promise<PermissionTestResponse> = testPermission({
  principal_type: "user",
  principal_id: "user-1",
  permission: "finding:view",
  scope_type: "project",
  scope_id: "project-1",
})
const currentActor: ActorMetadata = {
  actor_type: "user",
  actor_id: "user-1",
  display_name: "Alice",
  principal_type: "user",
  principal_id: "user-1",
  auth_method: "session",
  session_id: "session-1",
  machine_token_id: null,
  mixed_credentials_present: false,
  bearer_token_present: false,
  session_cookie_present: true,
  local_auth_enabled: true,
}
const changedCurrentUserPassword: Promise<void> = changeCurrentUserPassword({
  current_password: "correct horse battery staple",
  new_password: "new correct horse battery",
})
const accessList: Promise<AccessListResponse> = listAccessManagement()
const accessGroup: AccessGroup = {
  id: "group-1",
  name: "security-reviewers",
  display_name: "Security Reviewers",
  is_protected: false,
  created_at: "2026-05-08T12:00:00Z",
  updated_at: "2026-05-08T12:00:00Z",
}
const createdAccessGroup: Promise<AccessGroup> = createAccessGroup({
  name: "security-reviewers",
  display_name: "Security Reviewers",
})
const accessMembership: Promise<AccessMembership> = createAccessMembership({
  group_id: "group-1",
  principal_type: "user",
  principal_id: "user-1",
})
const accessPermission: Promise<AccessPermissionAssignment> = assignAccessPermission({
  principal_type: "group",
  principal_id: "group-1",
  permission: "finding:status_change:approve",
  effect: "allow",
  scope_type: "project",
  scope_id: "project-1",
})
const changedAccessUserPassword: Promise<void> = setAccessUserPassword("user-1", {
  new_password: "new correct horse battery",
})
const adminImportAttempt: AdminImportAttempt = {
  id: "attempt-1",
  project_id: "project-1",
  project_name: "Alpha",
  asset_id: "asset-1",
  asset_name: "API Image",
  asset_path: "images/api",
  uploader_principal_type: "user",
  uploader_principal_id: "user-1",
  uploader_display: "Alice",
  status: "failed",
  parser_name: "trivy-image-json",
  sanitized_message: "Invalid JSON report",
  correlation_id: "corr-1",
  metadata: {
    failure_category: "parser_error",
    raw_report_retained: false,
  },
  created_at: "2026-05-08T12:00:00Z",
  updated_at: "2026-05-08T12:01:00Z",
}
const adminImportHistory: Promise<AdminImportHistoryResponse> = listAdminImportHistory({
  limit: 25,
})
const adminImportUploaderLabel: string = importUploaderLabel(adminImportAttempt)
const userSession: UserSession = {
  id: "session-1",
  user_id: "user-1",
  username: "alice",
  display_name: "Alice",
  ip_address: "127.0.0.1",
  user_agent: "test-agent",
  created_at: "2026-05-08T12:00:00Z",
  updated_at: "2026-05-08T12:00:00Z",
  last_seen_at: "2026-05-08T12:00:00Z",
  idle_expires_at: "2026-05-08T12:30:00Z",
  expires_at: "2026-05-08T20:00:00Z",
  revoked_at: null,
  active: true,
}
const userSessions: Promise<UserSessionsResponse> = listUserSessions()
const revokedUserSession: Promise<UserSession> = revokeUserSession("session-1")
const securitySettings: Promise<SecuritySettings> = getSecuritySettings()
const updatedSecuritySettings: Promise<SecuritySettings> = updateSecuritySettings({
  force_peer_review_for_status_changes: true,
  session_idle_timeout_minutes: 45,
  session_absolute_timeout_minutes: 720,
})
const createdProject: Promise<Project> = createProject({
  slug: "mobile",
  name: "Mobile",
  description: "Mobile applications",
  require_peer_review_for_status_changes: true,
})
const updatedProject: Promise<Project> = updateProject("project-1", {
  slug: "mobile-renamed",
  name: "Mobile Renamed",
  require_peer_review_for_status_changes: true,
})
const createdFolder: Promise<Asset> = createFolder("project-1", {
  path: "apps/mobile",
})
const createdScanTarget: Promise<Asset> = createScanTarget("project-1", {
  folder_path: "apps/mobile",
  name: "iOS app",
  target_ref: "github.com/acme/mobile-ios",
})
const updatedAsset: Promise<Asset> = updateAsset("project-1", "asset-1", {
  name: "Renamed app",
  parent_id: null,
  sla_tracking_enabled: true,
  sla_reporting_enabled: null,
})
const comments: FindingComment[] = detail.comments
const requests: FindingStatusChangeRequest[] = detail.status_change_requests
const commentAuthorDisplay: string | null = comments[0]?.author_display ?? null
const requestRequesterDisplay: string | null = requests[0]?.requester_display ?? null
const requestReviewerDisplay: string | null = requests[0]?.reviewer_display ?? null
const createdComment: Promise<FindingComment> = createFindingComment("finding-1", {
  body: "Needs follow-up.",
})
const updatedDetail: Promise<FindingDetail> = updateFindingStatus("finding-1", {
  status: "fixed",
  comment: "Patched in the latest release.",
  require_peer_review: true,
})
const approvedStatusRequest: Promise<FindingDetail> = approveFindingStatusRequest(
  "finding-1",
  "request-1",
  {
    comment: "Looks good.",
  },
)
const approvedStatusRequestWithoutComment: Promise<FindingDetail> =
  approveFindingStatusRequest("finding-1", "request-1", {})
const rejectedStatusRequest: Promise<FindingDetail> = rejectFindingStatusRequest(
  "finding-1",
  "request-1",
  {
    comment: "Needs more evidence.",
  },
)

void auditEntry
void auditLog
void filteredFindings
void auditLogResponse
void findingAuditMetadata
void machineCredential
void machineCredentialWithSecret
void machineCredentials
void createdMachineCredential
void regeneratedMachineCredentialSecret
void revokedMachineCredential
void permissionTest
void currentActor
void changedCurrentUserPassword
void accessList
void accessGroup
void createdAccessGroup
void accessMembership
void accessPermission
void changedAccessUserPassword
void adminImportAttempt
void adminImportHistory
void adminImportUploaderLabel
void userSession
void userSessions
void revokedUserSession
void securitySettings
void updatedSecuritySettings
void createdProject
void updatedProject
void createdFolder
void createdScanTarget
void updatedAsset
void comments
void requests
void commentAuthorDisplay
void requestRequesterDisplay
void requestReviewerDisplay
void createdComment
void updatedDetail
void approvedStatusRequest
void approvedStatusRequestWithoutComment
void rejectedStatusRequest
