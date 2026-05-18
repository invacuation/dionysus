export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

export type SeverityCount = {
  severity: string
  count: number
}

export type ProjectRiskSummary = {
  project_id: string
  project_name: string
  open_count: number
  overdue_count: number
}

export type EstateOverview = {
  open_findings: number
  overdue_sla: number
  grace_period_risk: number
  severity_counts: SeverityCount[]
  highest_risk_projects: ProjectRiskSummary[]
}

export type FindingStatus =
  | "open"
  | "accepted_risk"
  | "false_positive"
  | "mitigated"
  | "suppressed"
  | "fixed"

export type FindingSortKey =
  | "severity"
  | "first_detected"
  | "last_seen"
  | "package"
  | "installed_version"
  | "fixed_version"
  | "identifier"
  | "project"
  | "status"
  | "sla_remaining"
  | "grace_remaining"

export type SortDirection = "asc" | "desc"

export type AuditLogParams = {
  event_type?: string
  project_id?: string
  target_type?: string
  target_id?: string
  created_from?: string
  created_to?: string
  limit?: number
}

export type AuditLogEntry = {
  id: string
  event_type: string
  actor_principal_type: string | null
  actor_principal_id: string | null
  actor_display: string | null
  target_type: string | null
  target_id: string | null
  project_id: string | null
  ip_address: string | null
  user_agent: string | null
  metadata: Record<string, unknown>
  created_at: string
}

export type AuditLogResponse = {
  events: AuditLogEntry[]
  event_types: string[]
}

export type AdminImportHistoryParams = {
  limit?: number
}

export type AdminImportAttempt = {
  id: string
  project_id: string
  project_name: string
  asset_id: string | null
  asset_name: string | null
  asset_path: string | null
  uploader_principal_type: string | null
  uploader_principal_id: string | null
  uploader_display: string | null
  status: string
  parser_name: string
  sanitized_message: string | null
  correlation_id: string | null
  metadata: Record<string, unknown>
  created_at: string
  updated_at: string
}

export type AdminImportHistoryResponse = {
  attempts: AdminImportAttempt[]
}

export type MachineCredential = {
  id: string
  name: string
  client_id: string
  is_active: boolean
  created_by_principal_type: string | null
  created_by_principal_id: string | null
  created_by_display: string | null
  created_at: string
  updated_at: string
  revoked_at: string | null
}

export type MachineCredentialWithSecret = MachineCredential & {
  client_secret: string
}

export type MachineCredentialsResponse = {
  credentials: MachineCredential[]
}

export type PermissionTestPrincipalType = "user" | "group" | "machine"

export type PermissionTestParams = {
  principal_type: PermissionTestPrincipalType
  principal_id: string
  permission: string
  scope_type?: string | null
  scope_id?: string | null
}

export type PermissionTestResponse = {
  allowed: boolean
  explanation: string
}

export type SecuritySettings = {
  force_peer_review_for_status_changes: boolean
  session_idle_timeout_minutes: number
  session_absolute_timeout_minutes: number
}

export type AccessPrincipalType = "user" | "group" | "machine"
export type PermissionEffect = "allow" | "deny"

export type AccessUser = {
  id: string
  username: string
  display_name: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export type AccessMachineCredential = {
  id: string
  name: string
  client_id: string
  is_active: boolean
  created_at: string
  updated_at: string
  revoked_at: string | null
}

export type AccessGroup = {
  id: string
  name: string
  display_name: string
  is_protected: boolean
  created_at: string
  updated_at: string
}

export type AccessMembership = {
  id: string
  group_id: string
  principal_type: AccessPrincipalType
  principal_id: string
  created_at: string
  updated_at: string
}

export type AccessPermissionAssignment = {
  id: string
  principal_type: AccessPrincipalType
  principal_id: string
  permission: string
  effect: PermissionEffect
  scope_type: string | null
  scope_id: string | null
  created_at: string
  updated_at: string
}

export type AccessListResponse = {
  users: AccessUser[]
  machine_credentials: AccessMachineCredential[]
  groups: AccessGroup[]
  memberships: AccessMembership[]
  permission_assignments: AccessPermissionAssignment[]
  available_permissions: string[]
}

export type CreateAccessGroupParams = {
  name: string
  display_name: string
}

export type CreateAccessMembershipParams = {
  group_id: string
  principal_type: AccessPrincipalType
  principal_id: string
}

export type AssignAccessPermissionParams = {
  principal_type: AccessPrincipalType
  principal_id: string
  permission: string
  effect: PermissionEffect
  scope_type?: string | null
  scope_id?: string | null
}

export type CreateAccessUserParams = {
  username: string
  display_name: string
  password: string
}

export type UserSession = {
  id: string
  user_id: string
  username: string
  display_name: string
  ip_address: string | null
  user_agent: string | null
  created_at: string
  updated_at: string
  last_seen_at: string
  idle_expires_at: string
  expires_at: string
  revoked_at: string | null
  active: boolean
}

export type UserSessionsResponse = {
  sessions: UserSession[]
}

export type CreateMachineCredentialParams = {
  name: string
}

export type MachineCredentialTokenOptions = {
  revoke_tokens?: boolean
}

export type FindingListParams = {
  project_id?: string
  asset_id?: string
  severity?: string
  status?: FindingStatus
  identifier?: string
  package?: string
  present_in_latest_scan?: boolean
  fix_available?: boolean
  sort?: FindingSortKey
  direction?: SortDirection
}

export type FindingRow = {
  id: string
  project_id: string
  project_name: string
  scan_target_id: string
  scan_target_name: string
  scan_target_path: string
  scan_target_ref: string | null
  scanner: string
  primary_identifier: string
  additional_identifiers: string[]
  package_name: string | null
  installed_version: string | null
  fixed_version: string | null
  severity: string
  cvss: Record<string, unknown>
  status: FindingStatus
  first_detected_at: string
  last_seen_at: string
  present_in_latest_scan: boolean
  sla_active: boolean
  sla_remaining_days: number | null
  grace_remaining_days: number | null
  sla_status: string
  sla_reason: string | null
  sla_days: number | null
  grace_days: number | null
  include_in_sla_reports: boolean
}

export type FindingListResponse = {
  rows: FindingRow[]
}

export type ProjectGroup = {
  id: string
  primary_identifier: string
  additional_identifiers: string[]
  status: FindingStatus
  first_detected_at: string
}

export type FindingComment = {
  id: string
  body: string
  author_principal_type: string
  author_principal_id: string
  author_display: string | null
  created_at: string
  is_system: boolean
  status_from: FindingStatus | null
  status_to: FindingStatus | null
}

export type FindingStatusChangeRequest = {
  id: string
  requester_principal_type: string
  requester_principal_id: string
  requester_display: string | null
  reviewer_principal_type: string | null
  reviewer_principal_id: string | null
  reviewer_display: string | null
  from_status: FindingStatus
  to_status: FindingStatus
  state: string
  comment: string | null
  decision_comment: string | null
  created_at: string
  decided_at: string | null
}

export type FindingDetail = FindingRow & {
  scanner_finding_id: string
  dedupe_key: string
  identifiers: string[]
  references: string[]
  description: string | null
  artifact_name: string | null
  artifact_type: string | null
  artifact_path: string | null
  source_evidence: Record<string, unknown>
  project_group: ProjectGroup | null
  peer_review_required_for_status_changes: boolean
  comments: FindingComment[]
  status_change_requests: FindingStatusChangeRequest[]
}

export type CreateFindingCommentParams = {
  body: string
}

export type UpdateFindingStatusParams = {
  status: FindingStatus
  comment: string
  require_peer_review?: boolean
}

export type ApproveFindingStatusRequestParams = {
  comment?: string | null
}

export type RejectFindingStatusRequestParams = {
  comment: string
}

export type ActorMetadata = {
  actor_type: string
  actor_id: string
  display_name: string
  principal_type: string
  principal_id: string
  auth_method: string
  session_id: string | null
  machine_token_id: string | null
  mixed_credentials_present: boolean
  bearer_token_present: boolean
  session_cookie_present: boolean
  local_auth_enabled: boolean
}

export type LoginCredentials = {
  username: string
  password: string
}

export type ChangeCurrentUserPasswordParams = {
  current_password: string
  new_password: string
}

export type SetAccessUserPasswordParams = {
  new_password: string
}

export type Project = {
  id: string
  slug: string
  name: string
  description: string | null
  sla_tracking_enabled: boolean
  sla_reporting_enabled: boolean
  require_peer_review_for_status_changes: boolean
  grace_period_enabled: boolean
  grace_period_percent: number
}

export type ProjectListResponse = {
  projects: Project[]
}

export type CreateProjectParams = {
  slug: string
  name: string
  description?: string
  sla_tracking_enabled?: boolean
  sla_reporting_enabled?: boolean
  require_peer_review_for_status_changes?: boolean
  grace_period_enabled?: boolean
  grace_period_percent?: number
}

export type UpdateProjectParams = {
  slug?: string
  name?: string
  sla_tracking_enabled?: boolean
  sla_reporting_enabled?: boolean
  require_peer_review_for_status_changes?: boolean
  grace_period_enabled?: boolean
  grace_period_percent?: number
}

export type Asset = {
  id: string
  parent_id: string | null
  path: string
  type: string
  name: string
  target_ref: string | null
  scan_label: string | null
  sla_tracking_enabled: boolean | null
  sla_reporting_enabled: boolean | null
  grace_period_enabled: boolean | null
  grace_period_percent: number | null
  sort_order: number
}

export type ProjectAssetsResponse = {
  project_id: string
  assets: Asset[]
}

export type CreateFolderParams = {
  path: string
}

export type CreateScanTargetParams = {
  folder_path: string
  name: string
  target_ref: string
  node_type?: string
  metadata?: Record<string, unknown>
}

export type UpdateAssetParams = {
  name?: string
  parent_id?: string | null
  sla_tracking_enabled?: boolean | null
  sla_reporting_enabled?: boolean | null
  grace_period_enabled?: boolean | null
  grace_period_percent?: number | null
}

export type ImportTrivyReportParams = {
  project_id: string
  folder_id?: string
  folder_path?: string
  asset_name?: string
  target_ref?: string
  scan_target_id?: string
  report_file: File
  scan_started_at?: string
}

export type ImportTrivyReportResponse = {
  import_attempt_id: string
  scan_id: string
  project_id: string
  scan_target_id: string
  scanner: string
  report_kind: string
  finding_count: number
  group_count: number
}

export type PreviewTrivyReportParams = {
  project_id: string
  report_file: File
}

export type TrivyImportPreviewResponse = {
  scanner: string
  report_kind: string
  tool_label: string
  detected_project_name: string | null
  detected_asset_name: string | null
  detected_target_ref: string | null
  scan_started_at: string | null
  finding_count: number
  group_count: number
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  })
  await assertOk(response)
  return (await response.json()) as T
}

export async function postJson<TResponse, TBody extends object>(
  path: string,
  body: TBody,
): Promise<TResponse> {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    credentials: "same-origin",
  })
  await assertOk(response)
  return (await response.json()) as TResponse
}

export async function patchJson<TResponse, TBody extends object>(
  path: string,
  body: TBody,
): Promise<TResponse> {
  const response = await fetch(path, {
    method: "PATCH",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    credentials: "same-origin",
  })
  await assertOk(response)
  return (await response.json()) as TResponse
}

export async function postFormData<TResponse>(
  path: string,
  body: FormData,
): Promise<TResponse> {
  const response = await fetch(path, {
    method: "POST",
    headers: { Accept: "application/json" },
    body,
    credentials: "same-origin",
  })
  await assertOk(response)
  return (await response.json()) as TResponse
}

export async function deleteRequest(path: string): Promise<void> {
  const response = await fetch(path, {
    method: "DELETE",
    credentials: "same-origin",
  })
  await assertOk(response)
}

export function getCurrentActor(): Promise<ActorMetadata> {
  return getJson<ActorMetadata>("/api/auth/me")
}

export function login(credentials: LoginCredentials): Promise<ActorMetadata> {
  return postJson<ActorMetadata, LoginCredentials>("/api/auth/session", credentials)
}

export function logout(): Promise<void> {
  return deleteRequest("/api/auth/session")
}

export async function changeCurrentUserPassword(
  params: ChangeCurrentUserPasswordParams,
): Promise<void> {
  const response = await fetch("/api/auth/password", {
    method: "PATCH",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(params),
    credentials: "same-origin",
  })
  await assertOk(response)
}

export function listProjects(): Promise<ProjectListResponse> {
  return getJson<ProjectListResponse>("/api/projects")
}

export function createProject(params: CreateProjectParams): Promise<Project> {
  return postJson<Project, CreateProjectParams>("/api/projects", params)
}

export function updateProject(projectId: string, params: UpdateProjectParams): Promise<Project> {
  return patchJson<Project, UpdateProjectParams>(
    `/api/projects/${encodeURIComponent(projectId)}`,
    params,
  )
}

export function deleteProject(projectId: string): Promise<void> {
  return deleteRequest(`/api/projects/${encodeURIComponent(projectId)}`)
}

export function listProjectAssets(projectId: string): Promise<ProjectAssetsResponse> {
  return getJson<ProjectAssetsResponse>(`/api/projects/${encodeURIComponent(projectId)}/assets`)
}

export function createFolder(projectId: string, params: CreateFolderParams): Promise<Asset> {
  return postJson<Asset, CreateFolderParams>(
    `/api/projects/${encodeURIComponent(projectId)}/folders`,
    params,
  )
}

export function createScanTarget(
  projectId: string,
  params: CreateScanTargetParams,
): Promise<Asset> {
  return postJson<Asset, CreateScanTargetParams>(
    `/api/projects/${encodeURIComponent(projectId)}/scan-targets`,
    params,
  )
}

export function updateAsset(
  projectId: string,
  assetId: string,
  params: UpdateAssetParams,
): Promise<Asset> {
  return patchJson<Asset, UpdateAssetParams>(
    `/api/projects/${encodeURIComponent(projectId)}/assets/${encodeURIComponent(assetId)}`,
    params,
  )
}

export function deleteAsset(projectId: string, assetId: string): Promise<void> {
  return deleteRequest(
    `/api/projects/${encodeURIComponent(projectId)}/assets/${encodeURIComponent(assetId)}`,
  )
}

export function importTrivyReport(
  params: ImportTrivyReportParams,
): Promise<ImportTrivyReportResponse> {
  const formData = new FormData()
  formData.set("project_id", params.project_id)
  if (params.folder_id?.trim()) {
    formData.set("folder_id", params.folder_id.trim())
  }
  if (params.folder_path?.trim()) {
    formData.set("folder_path", params.folder_path.trim())
  }
  if (params.asset_name?.trim()) {
    formData.set("asset_name", params.asset_name.trim())
  }
  if (params.target_ref?.trim()) {
    formData.set("target_ref", params.target_ref.trim())
  }
  if (params.scan_target_id?.trim()) {
    formData.set("scan_target_id", params.scan_target_id.trim())
  }
  formData.set("report_file", params.report_file)
  if (params.scan_started_at?.trim()) {
    formData.set("scan_started_at", params.scan_started_at.trim())
  }
  return postFormData<ImportTrivyReportResponse>("/api/imports/trivy", formData)
}

export function previewTrivyReport(
  params: PreviewTrivyReportParams,
): Promise<TrivyImportPreviewResponse> {
  const formData = new FormData()
  formData.set("project_id", params.project_id)
  formData.set("report_file", params.report_file)
  return postFormData<TrivyImportPreviewResponse>("/api/imports/trivy/preview", formData)
}

export function listFindings(params: FindingListParams): Promise<FindingListResponse> {
  const searchParams = new URLSearchParams()
  appendParam(searchParams, "project_id", params.project_id)
  appendParam(searchParams, "asset_id", params.asset_id)
  appendParam(searchParams, "severity", params.severity)
  appendParam(searchParams, "status", params.status)
  appendParam(searchParams, "identifier", params.identifier)
  appendParam(searchParams, "package", params.package)
  if (params.present_in_latest_scan !== undefined) {
    searchParams.set("present_in_latest_scan", String(params.present_in_latest_scan))
  }
  if (params.fix_available !== undefined) {
    searchParams.set("fix_available", String(params.fix_available))
  }
  appendParam(searchParams, "sort", params.sort)
  appendParam(searchParams, "direction", params.direction)

  const queryString = searchParams.toString()
  return getJson<FindingListResponse>(`/api/findings${queryString ? `?${queryString}` : ""}`)
}

export function listAuditLog(params: AuditLogParams): Promise<AuditLogResponse> {
  const searchParams = new URLSearchParams()
  appendParam(searchParams, "event_type", params.event_type)
  appendParam(searchParams, "project_id", params.project_id)
  appendParam(searchParams, "target_type", params.target_type)
  appendParam(searchParams, "target_id", params.target_id)
  appendParam(searchParams, "created_from", params.created_from)
  appendParam(searchParams, "created_to", params.created_to)
  if (params.limit !== undefined) {
    searchParams.set("limit", String(params.limit))
  }

  const queryString = searchParams.toString()
  return getJson<AuditLogResponse>(`/api/audit-log${queryString ? `?${queryString}` : ""}`)
}

export function listAdminImportHistory(
  params: AdminImportHistoryParams = {},
): Promise<AdminImportHistoryResponse> {
  const searchParams = new URLSearchParams()
  if (params.limit !== undefined) {
    searchParams.set("limit", String(params.limit))
  }

  const queryString = searchParams.toString()
  return getJson<AdminImportHistoryResponse>(
    `/api/admin/imports${queryString ? `?${queryString}` : ""}`,
  )
}

export function listMachineCredentials(): Promise<MachineCredentialsResponse> {
  return getJson<MachineCredentialsResponse>("/api/admin/machine-credentials")
}

export function listUserSessions(): Promise<UserSessionsResponse> {
  return getJson<UserSessionsResponse>("/api/admin/sessions")
}

export function revokeUserSession(sessionId: string): Promise<UserSession> {
  return postJson<UserSession, Record<string, never>>(
    `/api/admin/sessions/${encodeURIComponent(sessionId)}/revoke`,
    {},
  )
}

export function listAccessManagement(): Promise<AccessListResponse> {
  return getJson<AccessListResponse>("/api/admin/access")
}

export function createAccessGroup(params: CreateAccessGroupParams): Promise<AccessGroup> {
  return postJson<AccessGroup, CreateAccessGroupParams>("/api/admin/access/groups", params)
}

export function createAccessMembership(
  params: CreateAccessMembershipParams,
): Promise<AccessMembership> {
  return postJson<AccessMembership, CreateAccessMembershipParams>(
    "/api/admin/access/memberships",
    params,
  )
}

export function assignAccessPermission(
  params: AssignAccessPermissionParams,
): Promise<AccessPermissionAssignment> {
  return postJson<AccessPermissionAssignment, AssignAccessPermissionParams>(
    "/api/admin/access/permissions",
    params,
  )
}

export function createAccessUser(params: CreateAccessUserParams): Promise<AccessUser> {
  return postJson<AccessUser, CreateAccessUserParams>("/api/admin/access/users", params)
}

export async function setAccessUserPassword(
  userId: string,
  params: SetAccessUserPasswordParams,
): Promise<void> {
  const response = await fetch(
    `/api/admin/access/users/${encodeURIComponent(userId)}/password`,
    {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(params),
      credentials: "same-origin",
    },
  )
  await assertOk(response)
}

export function getSecuritySettings(): Promise<SecuritySettings> {
  return getJson<SecuritySettings>("/api/admin/security-settings")
}

export function updateSecuritySettings(params: SecuritySettings): Promise<SecuritySettings> {
  return patchJson<SecuritySettings, SecuritySettings>("/api/admin/security-settings", params)
}

export function testPermission(
  params: PermissionTestParams,
): Promise<PermissionTestResponse> {
  return postJson<PermissionTestResponse, PermissionTestParams>(
    "/api/admin/permission-test",
    params,
  )
}

export function createMachineCredential(
  params: CreateMachineCredentialParams,
): Promise<MachineCredentialWithSecret> {
  return postJson<MachineCredentialWithSecret, CreateMachineCredentialParams>(
    "/api/admin/machine-credentials",
    params,
  )
}

export function regenerateMachineCredentialSecret(
  credentialId: string,
  params: MachineCredentialTokenOptions = {},
): Promise<MachineCredentialWithSecret> {
  return postJson<MachineCredentialWithSecret, MachineCredentialTokenOptions>(
    `/api/admin/machine-credentials/${encodeURIComponent(credentialId)}/regenerate-secret`,
    params,
  )
}

export function revokeMachineCredential(
  credentialId: string,
  params: MachineCredentialTokenOptions = {},
): Promise<MachineCredential> {
  return postJson<MachineCredential, MachineCredentialTokenOptions>(
    `/api/admin/machine-credentials/${encodeURIComponent(credentialId)}/revoke`,
    params,
  )
}

export function getFinding(id: string): Promise<FindingDetail> {
  return getJson<FindingDetail>(`/api/findings/${encodeURIComponent(id)}`)
}

export function createFindingComment(
  findingId: string,
  params: CreateFindingCommentParams,
): Promise<FindingComment> {
  return postJson<FindingComment, CreateFindingCommentParams>(
    `/api/findings/${encodeURIComponent(findingId)}/comments`,
    params,
  )
}

export function updateFindingStatus(
  findingId: string,
  params: UpdateFindingStatusParams,
): Promise<FindingDetail> {
  return postJson<FindingDetail, UpdateFindingStatusParams>(
    `/api/findings/${encodeURIComponent(findingId)}/status`,
    params,
  )
}

export function approveFindingStatusRequest(
  findingId: string,
  requestId: string,
  params: ApproveFindingStatusRequestParams = {},
): Promise<FindingDetail> {
  return postJson<FindingDetail, ApproveFindingStatusRequestParams>(
    `/api/findings/${encodeURIComponent(findingId)}/status-requests/${encodeURIComponent(requestId)}/approve`,
    params,
  )
}

export function rejectFindingStatusRequest(
  findingId: string,
  requestId: string,
  params: RejectFindingStatusRequestParams,
): Promise<FindingDetail> {
  return postJson<FindingDetail, RejectFindingStatusRequestParams>(
    `/api/findings/${encodeURIComponent(findingId)}/status-requests/${encodeURIComponent(requestId)}/reject`,
    params,
  )
}

export function retractFindingStatusRequest(
  findingId: string,
  requestId: string,
): Promise<FindingDetail> {
  return deleteJson<FindingDetail>(
    `/api/findings/${encodeURIComponent(findingId)}/status-requests/${encodeURIComponent(requestId)}/retract`,
  )
}

export async function deleteJson<TResponse>(path: string): Promise<TResponse> {
  const response = await fetch(path, {
    method: "DELETE",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  })
  await assertOk(response)
  return (await response.json()) as TResponse
}

function appendParam(params: URLSearchParams, key: string, value: string | undefined): void {
  if (value?.trim()) {
    params.set(key, value.trim())
  }
}

async function assertOk(response: Response): Promise<void> {
  if (response.ok) {
    return
  }

  let message = `Request failed with status ${response.status}`
  const contentType = response.headers.get("content-type")
  if (contentType?.includes("application/json")) {
    const body = (await response.json().catch(() => null)) as { detail?: unknown } | null
    if (typeof body?.detail === "string") {
      message = body.detail
    }
  }

  throw new ApiError(message, response.status)
}
