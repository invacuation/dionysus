import {
  AlertCircle,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  KeyRound,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  assignAccessPermission,
  createAccessGroup,
  createAccessMembership,
  createMachineCredential,
  getSecuritySettings,
  listAdminImportHistory,
  listAccessManagement,
  listAuditLog,
  listMachineCredentials,
  listUserSessions,
  regenerateMachineCredentialSecret,
  revokeMachineCredential,
  revokeUserSession,
  testPermission,
  updateSecuritySettings,
  type AccessListResponse,
  type AccessPrincipalType,
  type AdminImportAttempt,
  type AssignAccessPermissionParams,
  type AuditLogEntry,
  type AuditLogParams,
  type AuditLogResponse,
  type MachineCredential,
  type MachineCredentialWithSecret,
  type PermissionTestParams,
  type PermissionTestPrincipalType,
  type PermissionTestResponse,
  type PermissionEffect,
  type SecuritySettings,
  type UserSession,
} from "@/lib/api"

type AuditLogFilters = {
  eventType: string
  actor: string
  target: string
  createdFrom: string
  createdTo: string
  limit: string
}

const defaultFilters: AuditLogFilters = {
  eventType: "",
  actor: "",
  target: "",
  createdFrom: "",
  createdTo: "",
  limit: "50",
}

type AdminTab =
  | "access"
  | "audit-log"
  | "import-history"
  | "machine-credentials"
  | "permission-tester"
  | "sessions"
  | "security-settings"
type CopyStatus = "idle" | "copied" | "failed"
type SecretPanelState = {
  action: "created" | "regenerated"
  credential: MachineCredentialWithSecret
}
type PermissionTesterForm = {
  principalType: PermissionTestPrincipalType
  principalId: string
  permission: string
  scopeType: string
  scopeId: string
}
type SecuritySettingsForm = {
  idleTimeoutMinutes: string
  absoluteTimeoutMinutes: string
}

const defaultPermissionTesterForm: PermissionTesterForm = {
  principalType: "user",
  principalId: "",
  permission: "",
  scopeType: "project",
  scopeId: "",
}

type AccessGroupForm = {
  name: string
  displayName: string
}

type AccessMembershipForm = {
  groupId: string
  principalType: AccessPrincipalType
  principalId: string
}

type AccessPermissionForm = {
  principalType: AccessPrincipalType
  principalId: string
  permission: string
  effect: PermissionEffect
  scopeType: string
  scopeId: string
}

const defaultAccessGroupForm: AccessGroupForm = { name: "", displayName: "" }
const defaultAccessMembershipForm: AccessMembershipForm = {
  groupId: "",
  principalType: "user",
  principalId: "",
}
const defaultAccessPermissionForm: AccessPermissionForm = {
  principalType: "user",
  principalId: "",
  permission: "",
  effect: "allow",
  scopeType: "project",
  scopeId: "",
}

export function AdminPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<AdminTab>("audit-log")
  const [draftFilters, setDraftFilters] = useState<AuditLogFilters>(defaultFilters)
  const [appliedFilters, setAppliedFilters] = useState<AuditLogFilters>(defaultFilters)
  const [newCredentialName, setNewCredentialName] = useState("")
  const [secretPanel, setSecretPanel] = useState<SecretPanelState | null>(null)
  const [copyStatus, setCopyStatus] = useState<CopyStatus>("idle")
  const params = useMemo(() => auditLogParams(appliedFilters), [appliedFilters])

  const auditLogQuery = useQuery({
    queryKey: ["audit-log", params],
    queryFn: () => listAuditLog(params),
  })

  const accessQuery = useQuery({
    queryKey: ["access-management"],
    queryFn: listAccessManagement,
  })

  const machineCredentialsQuery = useQuery({
    queryKey: ["machine-credentials"],
    queryFn: listMachineCredentials,
  })

  const userSessionsQuery = useQuery({
    queryKey: ["user-sessions"],
    queryFn: listUserSessions,
  })

  const importHistoryQuery = useQuery({
    queryKey: ["admin-import-history"],
    queryFn: () => listAdminImportHistory({ limit: 50 }),
  })

  const securitySettingsQuery = useQuery({
    queryKey: ["security-settings"],
    queryFn: getSecuritySettings,
  })

  const invalidateAdminQueries = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["machine-credentials"] }),
      queryClient.invalidateQueries({ queryKey: ["access-management"] }),
      queryClient.invalidateQueries({ queryKey: ["user-sessions"] }),
      queryClient.invalidateQueries({ queryKey: ["security-settings"] }),
      queryClient.invalidateQueries({ queryKey: ["audit-log"] }),
      queryClient.invalidateQueries({ queryKey: ["admin-import-history"] }),
    ])
  }

  const createCredentialMutation = useMutation({
    mutationFn: createMachineCredential,
    onSuccess: async (credential) => {
      setSecretPanel({ action: "created", credential })
      setCopyStatus("idle")
      setNewCredentialName("")
      await invalidateAdminQueries()
    },
  })

  const regenerateSecretMutation = useMutation({
    mutationFn: ({ credentialId }: { credentialId: string }) =>
      regenerateMachineCredentialSecret(credentialId, { revoke_tokens: true }),
    onSuccess: async (credential) => {
      setSecretPanel({ action: "regenerated", credential })
      setCopyStatus("idle")
      await invalidateAdminQueries()
    },
  })

  const revokeCredentialMutation = useMutation({
    mutationFn: ({ credentialId }: { credentialId: string }) =>
      revokeMachineCredential(credentialId, { revoke_tokens: true }),
    onSuccess: async () => {
      await invalidateAdminQueries()
    },
  })

  const revokeSessionMutation = useMutation({
    mutationFn: ({ sessionId }: { sessionId: string }) => revokeUserSession(sessionId),
    onSuccess: async () => {
      await invalidateAdminQueries()
    },
  })

  const updateSecuritySettingsMutation = useMutation({
    mutationFn: updateSecuritySettings,
    onSuccess: async () => {
      await invalidateAdminQueries()
    },
  })

  const events = auditLogQuery.data?.events ?? []
  const eventTypes = auditLogQuery.data?.event_types ?? []
  const credentials = machineCredentialsQuery.data?.credentials ?? []
  const userSessions = userSessionsQuery.data?.sessions ?? []
  const importAttempts = importHistoryQuery.data?.attempts ?? []
  const isCredentialActionPending =
    createCredentialMutation.isPending ||
    regenerateSecretMutation.isPending ||
    revokeCredentialMutation.isPending

  const handleCreateCredential = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const name = newCredentialName.trim()
    if (!name) {
      return
    }
    createCredentialMutation.mutate({ name })
  }

  const handleCopySecret = async () => {
    if (!secretPanel) {
      return
    }
    if (!navigator.clipboard?.writeText) {
      setCopyStatus("failed")
      return
    }

    try {
      await navigator.clipboard.writeText(secretPanel.credential.client_secret)
      setCopyStatus("copied")
    } catch {
      setCopyStatus("failed")
    }
  }

  const handleRevokeCredential = (credential: MachineCredential) => {
    const confirmed = window.confirm(`Revoke machine credential "${credential.name}"?`)
    if (!confirmed) {
      return
    }
    revokeCredentialMutation.mutate({ credentialId: credential.id })
  }

  const handleRevokeSession = (session: UserSession) => {
    const confirmed = window.confirm(`Revoke session for "${session.display_name}"?`)
    if (!confirmed) {
      return
    }
    revokeSessionMutation.mutate({ sessionId: session.id })
  }

  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-normal">Admin</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Review application activity and security-relevant changes.
          </p>
        </div>
      </header>

      <div className="inline-flex rounded-md border bg-card p-1">
        <TabButton active={activeTab === "audit-log"} onClick={() => setActiveTab("audit-log")}>
          Audit Log
        </TabButton>
        <TabButton active={activeTab === "access"} onClick={() => setActiveTab("access")}>
          Access
        </TabButton>
        <TabButton
          active={activeTab === "import-history"}
          onClick={() => setActiveTab("import-history")}
        >
          Import History
        </TabButton>
        <TabButton
          active={activeTab === "machine-credentials"}
          onClick={() => setActiveTab("machine-credentials")}
        >
          Machine Credentials
        </TabButton>
        <TabButton active={activeTab === "sessions"} onClick={() => setActiveTab("sessions")}>
          Sessions
        </TabButton>
        <TabButton
          active={activeTab === "security-settings"}
          onClick={() => setActiveTab("security-settings")}
        >
          Security Settings
        </TabButton>
        <TabButton
          active={activeTab === "permission-tester"}
          onClick={() => setActiveTab("permission-tester")}
        >
          Permission Tester
        </TabButton>
      </div>

      {activeTab === "audit-log" ? (
        <AuditLogSection
          appliedFilters={appliedFilters}
          auditLogQuery={auditLogQuery}
          draftFilters={draftFilters}
          events={events}
          eventTypes={eventTypes}
          setAppliedFilters={setAppliedFilters}
          setDraftFilters={setDraftFilters}
        />
      ) : activeTab === "access" ? (
        <AccessManagementSection
          access={accessQuery.data ?? null}
          error={accessQuery.error}
          isError={accessQuery.isError}
          isLoading={accessQuery.isPending}
          onChanged={invalidateAdminQueries}
          onRefresh={() => void accessQuery.refetch()}
        />
      ) : activeTab === "import-history" ? (
        <ImportHistorySection
          attempts={importAttempts}
          error={importHistoryQuery.error}
          isError={importHistoryQuery.isError}
          isLoading={importHistoryQuery.isPending}
          onRefresh={() => void importHistoryQuery.refetch()}
        />
      ) : activeTab === "machine-credentials" ? (
        <div className="space-y-3">
          <section className="grid gap-3 rounded-lg border bg-card p-3 lg:grid-cols-[minmax(18rem,28rem)_1fr] lg:items-end">
            <form className="flex gap-2" onSubmit={handleCreateCredential}>
              <Field label="Name">
                <Input
                  disabled={createCredentialMutation.isPending}
                  onChange={(event) => setNewCredentialName(event.target.value)}
                  placeholder="ci-runner"
                  value={newCredentialName}
                />
              </Field>
              <div className="self-end">
                <Button
                  disabled={createCredentialMutation.isPending || !newCredentialName.trim()}
                  size="sm"
                  type="submit"
                >
                  <KeyRound className="size-4" aria-hidden="true" />
                  <span>{createCredentialMutation.isPending ? "Creating..." : "Create"}</span>
                </Button>
              </div>
            </form>

            <div className="flex justify-end self-end">
              <Button
                disabled={machineCredentialsQuery.isFetching}
                onClick={() => void machineCredentialsQuery.refetch()}
                size="sm"
                type="button"
                variant="outline"
              >
                <RefreshCw className="size-4" aria-hidden="true" />
                <span>Refresh</span>
              </Button>
            </div>
          </section>

          {secretPanel ? (
            <OneTimeSecretPanel
              copyStatus={copyStatus}
              onCopy={handleCopySecret}
              onDismiss={() => {
                setSecretPanel(null)
                setCopyStatus("idle")
              }}
              secretPanel={secretPanel}
            />
          ) : null}

          <MutationError
            error={
              createCredentialMutation.error ??
              regenerateSecretMutation.error ??
              revokeCredentialMutation.error
            }
          />

          <Card className="gap-0 overflow-hidden py-0">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <div>
                <h2 className="text-sm font-semibold">Machine Credentials</h2>
                <p className="text-xs text-muted-foreground">
                  {credentialResultLabel(machineCredentialsQuery.isPending, credentials.length)}
                </p>
              </div>
            </div>
            <CardContent className="p-0">
              <MachineCredentialsTable
                actionCredentialId={
                  regenerateSecretMutation.variables?.credentialId ??
                  revokeCredentialMutation.variables?.credentialId ??
                  null
                }
                credentials={credentials}
                error={machineCredentialsQuery.error}
                isActionPending={isCredentialActionPending}
                isError={machineCredentialsQuery.isError}
                isLoading={machineCredentialsQuery.isPending}
                onRegenerate={(credential) =>
                  regenerateSecretMutation.mutate({ credentialId: credential.id })
                }
                onRevoke={handleRevokeCredential}
              />
            </CardContent>
          </Card>
        </div>
      ) : activeTab === "sessions" ? (
        <SessionsSection
          actionSessionId={revokeSessionMutation.variables?.sessionId ?? null}
          error={userSessionsQuery.error}
          isActionPending={revokeSessionMutation.isPending}
          isError={userSessionsQuery.isError}
          isLoading={userSessionsQuery.isPending}
          onRefresh={() => void userSessionsQuery.refetch()}
          onRevoke={handleRevokeSession}
          sessions={userSessions}
        />
      ) : activeTab === "security-settings" ? (
        <SecuritySettingsSection
          error={securitySettingsQuery.error}
          isError={securitySettingsQuery.isError}
          isLoading={securitySettingsQuery.isPending}
          isSaving={updateSecuritySettingsMutation.isPending}
          mutationError={updateSecuritySettingsMutation.error}
          onRefresh={() => void securitySettingsQuery.refetch()}
          onSave={(settings) => updateSecuritySettingsMutation.mutate(settings)}
          settings={securitySettingsQuery.data ?? null}
        />
      ) : (
        <PermissionTesterSection access={accessQuery.data ?? null} />
      )}
    </div>
  )
}

function AuditLogSection({
  appliedFilters,
  auditLogQuery,
  draftFilters,
  events,
  eventTypes,
  setAppliedFilters,
  setDraftFilters,
}: {
  appliedFilters: AuditLogFilters
  auditLogQuery: ReturnType<typeof useQuery<AuditLogResponse>>
  draftFilters: AuditLogFilters
  events: AuditLogEntry[]
  eventTypes: string[]
  setAppliedFilters: React.Dispatch<React.SetStateAction<AuditLogFilters>>
  setDraftFilters: React.Dispatch<React.SetStateAction<AuditLogFilters>>
}) {
  const eventTypeOptions = useMemo(
    () =>
      Array.from(
        new Set(
          eventTypes
            .filter((eventType) => eventType.trim())
            .sort((a, b) => a.localeCompare(b)),
        ),
      ),
    [eventTypes],
  )
  const visibleEvents = useMemo(
    () =>
      filterAuditLogEvents(events, {
        actor: appliedFilters.actor,
        target: appliedFilters.target,
      }),
    [appliedFilters.actor, appliedFilters.target, events],
  )

  return (
    <>
      <section className="grid gap-3 rounded-lg border bg-card p-3 md:grid-cols-2 lg:grid-cols-[repeat(6,minmax(0,1fr))_auto] lg:items-end">
        <Field label="Event Type">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              className="pl-9"
              list="audit-event-types"
              onChange={(event) =>
                setDraftFilters((current) => ({ ...current, eventType: event.target.value }))
              }
              placeholder="finding.status.changed"
              value={draftFilters.eventType}
            />
            <datalist id="audit-event-types">
              {eventTypeOptions.map((eventType) => (
                <option key={eventType} value={eventType} />
              ))}
            </datalist>
          </div>
        </Field>

        <Field label="Actor">
          <Input
            onChange={(event) =>
              setDraftFilters((current) => ({ ...current, actor: event.target.value }))
            }
            placeholder="Alice, user, credential id"
            value={draftFilters.actor}
          />
        </Field>

        <Field label="Target">
          <Input
            onChange={(event) =>
              setDraftFilters((current) => ({ ...current, target: event.target.value }))
            }
            placeholder="finding, project id, metadata"
            value={draftFilters.target}
          />
        </Field>

        <Field label="From">
          <Input
            onChange={(event) =>
              setDraftFilters((current) => ({ ...current, createdFrom: event.target.value }))
            }
            type="datetime-local"
            value={draftFilters.createdFrom}
          />
        </Field>

        <Field label="To">
          <Input
            onChange={(event) =>
              setDraftFilters((current) => ({ ...current, createdTo: event.target.value }))
            }
            type="datetime-local"
            value={draftFilters.createdTo}
          />
        </Field>

        <Field label="Limit">
          <Input
            min={1}
            onChange={(event) =>
              setDraftFilters((current) => ({ ...current, limit: event.target.value }))
            }
            placeholder="50"
            type="number"
            value={draftFilters.limit}
          />
        </Field>

        <div className="flex gap-2">
          <Button
            disabled={auditLogQuery.isFetching}
            onClick={() => setAppliedFilters(normalizeFilters(draftFilters))}
            size="sm"
            type="button"
          >
            <RefreshCw className="size-4" aria-hidden="true" />
            <span>{auditLogQuery.isFetching ? "Loading..." : "Apply"}</span>
          </Button>
          <Button
            disabled={isDefaultFilters(draftFilters) && isDefaultFilters(appliedFilters)}
            onClick={() => {
              setDraftFilters(defaultFilters)
              setAppliedFilters(defaultFilters)
            }}
            size="sm"
            type="button"
            variant="outline"
          >
            Clear
          </Button>
        </div>
      </section>

      <Card className="gap-0 overflow-hidden py-0">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold">Audit Log</h2>
            <p className="text-xs text-muted-foreground">
              {resultLabel(auditLogQuery.isPending, visibleEvents.length)}
            </p>
          </div>
          <Button
            disabled={auditLogQuery.isFetching}
            onClick={() => void auditLogQuery.refetch()}
            size="sm"
            type="button"
            variant="outline"
          >
            <RefreshCw className="size-4" aria-hidden="true" />
            <span>Refresh</span>
          </Button>
        </div>
        <CardContent className="p-0">
          <AuditLogTable
            error={auditLogQuery.error}
            events={visibleEvents}
            isError={auditLogQuery.isError}
            isLoading={auditLogQuery.isPending}
          />
        </CardContent>
      </Card>
    </>
  )
}

function ImportHistorySection({
  attempts,
  error,
  isError,
  isLoading,
  onRefresh,
}: {
  attempts: AdminImportAttempt[]
  error: Error | null
  isError: boolean
  isLoading: boolean
  onRefresh: () => void
}) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Import History</h2>
          <p className="text-xs text-muted-foreground">
            {importHistoryResultLabel(isLoading, attempts.length)}
          </p>
        </div>
        <Button disabled={isLoading} onClick={onRefresh} size="sm" type="button" variant="outline">
          <RefreshCw className="size-4" aria-hidden="true" />
          <span>Refresh</span>
        </Button>
      </div>
      <CardContent className="p-0">
        <ImportHistoryTable
          attempts={attempts}
          error={error}
          isError={isError}
          isLoading={isLoading}
        />
      </CardContent>
    </Card>
  )
}

function TabButton({
  active,
  children,
  onClick,
}: {
  active: boolean
  children: React.ReactNode
  onClick: () => void
}) {
  return (
    <button
      aria-current={active ? "page" : undefined}
      className={
        active
          ? "rounded-sm bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground"
          : "rounded-sm px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      }
      onClick={onClick}
      type="button"
    >
      {children}
    </button>
  )
}

function OneTimeSecretPanel({
  copyStatus,
  onCopy,
  onDismiss,
  secretPanel,
}: {
  copyStatus: CopyStatus
  onCopy: () => void
  onDismiss: () => void
  secretPanel: SecretPanelState
}) {
  return (
    <section className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-950">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="space-y-2">
          <div>
            <h2 className="text-sm font-semibold">
              Secret {secretPanel.action === "created" ? "created" : "regenerated"}
            </h2>
            <p className="text-xs">
              This client secret will not be shown again. Store it before leaving this page.
            </p>
          </div>
          <div className="grid gap-2 text-xs md:grid-cols-2">
            <SecretValue label="Client ID" value={secretPanel.credential.client_id} />
            <SecretValue label="Client secret" value={secretPanel.credential.client_secret} />
          </div>
          {copyStatus === "failed" ? (
            <p className="text-xs">
              Copy failed or is unavailable. Select the secret above and copy it manually.
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 gap-2">
          <Button onClick={onCopy} size="sm" type="button" variant="outline">
            {copyStatus === "copied" ? (
              <Check className="size-4" aria-hidden="true" />
            ) : (
              <Copy className="size-4" aria-hidden="true" />
            )}
            <span>{copyStatus === "copied" ? "Copied" : "Copy secret"}</span>
          </Button>
          <Button onClick={onDismiss} size="sm" type="button" variant="ghost">
            Dismiss
          </Button>
        </div>
      </div>
    </section>
  )
}

function SecretValue({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 font-medium">{label}</div>
      <code className="block max-w-full select-all overflow-x-auto rounded-md bg-white/80 px-2 py-1.5 font-mono text-xs">
        {value}
      </code>
    </div>
  )
}

function AccessManagementSection({
  access,
  error,
  isError,
  isLoading,
  onChanged,
  onRefresh,
}: {
  access: AccessListResponse | null
  error: Error | null
  isError: boolean
  isLoading: boolean
  onChanged: () => Promise<void>
  onRefresh: () => void
}) {
  const [groupForm, setGroupForm] = useState<AccessGroupForm>(defaultAccessGroupForm)
  const [membershipForm, setMembershipForm] =
    useState<AccessMembershipForm>(defaultAccessMembershipForm)
  const [permissionForm, setPermissionForm] =
    useState<AccessPermissionForm>(defaultAccessPermissionForm)

  const createGroupMutation = useMutation({
    mutationFn: () =>
      createAccessGroup({
        name: groupForm.name.trim(),
        display_name: groupForm.displayName.trim(),
      }),
    onSuccess: async () => {
      setGroupForm(defaultAccessGroupForm)
      await onChanged()
    },
  })
  const createMembershipMutation = useMutation({
    mutationFn: () =>
      createAccessMembership({
        group_id: membershipForm.groupId,
        principal_type: membershipForm.principalType,
        principal_id: membershipForm.principalId.trim(),
      }),
    onSuccess: async () => {
      setMembershipForm((current) => ({ ...current, principalId: "" }))
      await onChanged()
    },
  })
  const assignPermissionMutation = useMutation({
    mutationFn: () => assignAccessPermission(normalizeAccessPermissionForm(permissionForm)),
    onSuccess: async () => {
      setPermissionForm(defaultAccessPermissionForm)
      await onChanged()
    },
  })

  if (isLoading) {
    return <StateMessage label="Loading access data..." />
  }

  if (isError || !access) {
    return (
      <StateMessage
        label={error?.message ?? "Unable to load access data from the backend API."}
        tone="error"
      />
    )
  }

  const canCreateGroup = groupForm.name.trim().length > 0 && groupForm.displayName.trim().length > 0
  const canCreateMembership =
    membershipForm.groupId.length > 0 && membershipForm.principalId.trim().length > 0
  const normalizedPermission = normalizeAccessPermissionForm(permissionForm)
  const canAssignPermission =
    normalizedPermission.principal_id.length > 0 && normalizedPermission.permission.length > 0
  const availablePermissions = access.available_permissions

  return (
    <div className="space-y-4">
      <section className="grid gap-3 md:grid-cols-4">
        <AccessMetric label="Users" value={access.users.length} />
        <AccessMetric label="Groups" value={access.groups.length} />
        <AccessMetric label="Machine Credentials" value={access.machine_credentials.length} />
        <AccessMetric label="Permissions" value={access.permission_assignments.length} />
      </section>

      <section className="grid gap-3 xl:grid-cols-3">
        <Card className="py-0">
          <CardContent className="space-y-3 p-4">
            <h2 className="text-sm font-semibold">Create Group</h2>
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault()
                if (canCreateGroup) {
                  createGroupMutation.mutate()
                }
              }}
            >
              <Field label="Name">
                <Input
                  onChange={(event) =>
                    setGroupForm((current) => ({ ...current, name: event.target.value }))
                  }
                  placeholder="project-reviewers"
                  value={groupForm.name}
                />
              </Field>
              <Field label="Display Name">
                <Input
                  onChange={(event) =>
                    setGroupForm((current) => ({ ...current, displayName: event.target.value }))
                  }
                  placeholder="Project Reviewers"
                  value={groupForm.displayName}
                />
              </Field>
              <MutationError error={createGroupMutation.error} />
              <Button
                disabled={!canCreateGroup || createGroupMutation.isPending}
                size="sm"
                type="submit"
              >
                {createGroupMutation.isPending ? "Creating..." : "Create group"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="py-0">
          <CardContent className="space-y-3 p-4">
            <h2 className="text-sm font-semibold">Add Membership</h2>
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault()
                if (canCreateMembership) {
                  createMembershipMutation.mutate()
                }
              }}
            >
              <Field label="Group">
                <Select
                  onChange={(value) =>
                    setMembershipForm((current) => ({ ...current, groupId: value }))
                  }
                  value={membershipForm.groupId}
                >
                  <option value="">Select group</option>
                  {access.groups.map((group) => (
                    <option key={group.id} value={group.id}>
                      {group.display_name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Principal Type">
                <Select
                  onChange={(value) =>
                    setMembershipForm((current) => ({
                      ...current,
                      principalType: value as AccessPrincipalType,
                    }))
                  }
                  value={membershipForm.principalType}
                >
                  <option value="user">User</option>
                  <option value="machine">Machine</option>
                  <option value="group">Group</option>
                </Select>
              </Field>
              <Field label="Principal ID">
                <Input
                  onChange={(event) =>
                    setMembershipForm((current) => ({
                      ...current,
                      principalId: event.target.value,
                    }))
                  }
                  placeholder="principal UUID"
                  value={membershipForm.principalId}
                />
              </Field>
              <MutationError error={createMembershipMutation.error} />
              <Button
                disabled={!canCreateMembership || createMembershipMutation.isPending}
                size="sm"
                type="submit"
              >
                {createMembershipMutation.isPending ? "Adding..." : "Add membership"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="py-0">
          <CardContent className="space-y-3 p-4">
            <h2 className="text-sm font-semibold">Assign Permission</h2>
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault()
                if (canAssignPermission) {
                  assignPermissionMutation.mutate()
                }
              }}
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Principal Type">
                  <Select
                    onChange={(value) =>
                      setPermissionForm((current) => ({
                        ...current,
                        principalType: value as AccessPrincipalType,
                      }))
                    }
                    value={permissionForm.principalType}
                  >
                    <option value="user">User</option>
                    <option value="machine">Machine</option>
                    <option value="group">Group</option>
                  </Select>
                </Field>
                <Field label="Effect">
                  <Select
                    onChange={(value) =>
                      setPermissionForm((current) => ({
                        ...current,
                        effect: value as PermissionEffect,
                      }))
                    }
                    value={permissionForm.effect}
                  >
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </Select>
                </Field>
              </div>
              <Field label="Principal ID">
                <Input
                  onChange={(event) =>
                    setPermissionForm((current) => ({
                      ...current,
                      principalId: event.target.value,
                    }))
                  }
                  placeholder="principal UUID"
                  value={permissionForm.principalId}
                />
              </Field>
              <Field label="Permission">
                <Input
                  list="access-permission-options"
                  onChange={(event) =>
                    setPermissionForm((current) => ({
                      ...current,
                      permission: event.target.value,
                    }))
                  }
                  placeholder="finding:view"
                  value={permissionForm.permission}
                />
                <PermissionOptionsDatalist id="access-permission-options" permissions={availablePermissions} />
              </Field>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Scope Type">
                  <Input
                    onChange={(event) =>
                      setPermissionForm((current) => ({
                        ...current,
                        scopeType: event.target.value,
                      }))
                    }
                    placeholder="project"
                    value={permissionForm.scopeType}
                  />
                </Field>
                <Field label="Scope ID">
                  <Input
                    onChange={(event) =>
                      setPermissionForm((current) => ({
                        ...current,
                        scopeId: event.target.value,
                      }))
                    }
                    placeholder="project UUID"
                    value={permissionForm.scopeId}
                  />
                </Field>
              </div>
              <MutationError error={assignPermissionMutation.error} />
              <Button
                disabled={!canAssignPermission || assignPermissionMutation.isPending}
                size="sm"
                type="submit"
              >
                {assignPermissionMutation.isPending ? "Assigning..." : "Assign permission"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </section>

      <div className="flex justify-end">
        <Button onClick={onRefresh} size="sm" type="button" variant="outline">
          <RefreshCw className="size-4" aria-hidden="true" />
          <span>Refresh</span>
        </Button>
      </div>

      <section className="grid gap-4 xl:grid-cols-2">
        <AccessGroupsCard access={access} />
        <AccessPrincipalsCard access={access} />
      </section>

      <AccessPermissionsCard access={access} />
    </div>
  )
}

function PermissionTesterSection({ access }: { access: AccessListResponse | null }) {
  const [form, setForm] = useState<PermissionTesterForm>(defaultPermissionTesterForm)
  const [result, setResult] = useState<PermissionTestResponse | null>(null)
  const principalOptions = useMemo(
    () => permissionTesterPrincipalOptions(access, form.principalType),
    [access, form.principalType],
  )
  const availablePermissions = permissionOptionsForAccess(access)
  const mutation = useMutation({
    mutationFn: (params: PermissionTestParams) => testPermission(params),
    onSuccess: (response) => setResult(response),
  })
  const normalized = normalizePermissionTesterForm(form)
  const canSubmit =
    normalized.principal_id.length > 0 &&
    normalized.permission.length > 0 &&
    !mutation.isPending

  useEffect(() => {
    const nextPrincipalId = permissionTesterPrincipalIdForType(
      form.principalId,
      principalOptions,
    )
    if (nextPrincipalId !== form.principalId) {
      setForm((current) => ({ ...current, principalId: nextPrincipalId }))
      setResult(null)
    }
  }, [form.principalId, principalOptions])

  const updateForm = <Key extends keyof PermissionTesterForm>(
    key: Key,
    value: PermissionTesterForm[Key],
  ) => {
    setForm((current) => ({ ...current, [key]: value }))
    setResult(null)
  }

  return (
    <div className="space-y-3">
      <form
        className="grid gap-3 rounded-lg border bg-card p-3 lg:grid-cols-[10rem_repeat(4,minmax(0,1fr))_auto] lg:items-end"
        onSubmit={(event) => {
          event.preventDefault()
          if (!canSubmit) {
            return
          }
          mutation.mutate(normalized)
        }}
      >
        <Field label="Principal Type">
          <select
            className="flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
            onChange={(event) => {
              const principalType = event.target.value as PermissionTestPrincipalType
              setForm((current) => ({
                ...current,
                principalType,
                principalId: permissionTesterPrincipalIdForType(
                  "",
                  permissionTesterPrincipalOptions(access, principalType),
                ),
              }))
              setResult(null)
            }}
            value={form.principalType}
          >
            <option value="user">User</option>
            <option value="group">Group</option>
            <option value="machine">Machine</option>
          </select>
        </Field>

        <Field label="Principal ID">
          <select
            className="flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={principalOptions.length === 0}
            onChange={(event) => updateForm("principalId", event.target.value)}
            value={form.principalId}
          >
            {principalOptions.length === 0 ? (
              <option value="">No principals available</option>
            ) : (
              principalOptions.map((principal) => (
                <option key={principal.id} value={principal.id}>
                  {principal.label}
                </option>
              ))
            )}
          </select>
        </Field>

        <Field label="Permission">
          <Input
            list="permission-tester-permission-options"
            onChange={(event) => updateForm("permission", event.target.value)}
            placeholder="finding:status_change:approve"
            value={form.permission}
          />
          <PermissionOptionsDatalist
            id="permission-tester-permission-options"
            permissions={availablePermissions}
          />
        </Field>

        <Field label="Scope Type">
          <Input
            onChange={(event) => updateForm("scopeType", event.target.value)}
            placeholder="project"
            value={form.scopeType}
          />
        </Field>

        <Field label="Scope ID">
          <Input
            onChange={(event) => updateForm("scopeId", event.target.value)}
            placeholder="project UUID"
            value={form.scopeId}
          />
        </Field>

        <Button disabled={!canSubmit} size="sm" type="submit">
          <ShieldCheck className="size-4" aria-hidden="true" />
          <span>{mutation.isPending ? "Testing..." : "Test"}</span>
        </Button>
      </form>

      <MutationError error={mutation.error} />

      {result ? (
        <Card className="py-0">
          <CardContent className="flex flex-col gap-2 p-4">
            <div className="flex items-center gap-2">
              <Badge variant={result.allowed ? "default" : "destructive"}>
                {result.allowed ? "Allowed" : "Denied"}
              </Badge>
              <h2 className="text-sm font-semibold">Permission Result</h2>
            </div>
            <p className="text-sm text-muted-foreground">{result.explanation}</p>
          </CardContent>
        </Card>
      ) : (
        <Card className="py-0">
          <CardContent className="p-4 text-sm text-muted-foreground">
            Enter a principal, permission, and scope to preview the effective permission decision.
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function SessionsSection({
  actionSessionId,
  error,
  isActionPending,
  isError,
  isLoading,
  onRefresh,
  onRevoke,
  sessions,
}: {
  actionSessionId: string | null
  error: Error | null
  isActionPending: boolean
  isError: boolean
  isLoading: boolean
  onRefresh: () => void
  onRevoke: (session: UserSession) => void
  sessions: UserSession[]
}) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">User Sessions</h2>
          <p className="text-xs text-muted-foreground">
            {sessionResultLabel(isLoading, sessions.length)}
          </p>
        </div>
        <Button disabled={isLoading} onClick={onRefresh} size="sm" type="button" variant="outline">
          <RefreshCw className="size-4" aria-hidden="true" />
          <span>Refresh</span>
        </Button>
      </div>
      <CardContent className="p-0">
        <SessionsTable
          actionSessionId={actionSessionId}
          error={error}
          isActionPending={isActionPending}
          isError={isError}
          isLoading={isLoading}
          onRevoke={onRevoke}
          sessions={sessions}
        />
      </CardContent>
    </Card>
  )
}

function SecuritySettingsSection({
  error,
  isError,
  isLoading,
  isSaving,
  mutationError,
  onRefresh,
  onSave,
  settings,
}: {
  error: Error | null
  isError: boolean
  isLoading: boolean
  isSaving: boolean
  mutationError: Error | null
  onRefresh: () => void
  onSave: (settings: SecuritySettings) => void
  settings: SecuritySettings | null
}) {
  const [form, setForm] = useState<SecuritySettingsForm>({
    idleTimeoutMinutes: "",
    absoluteTimeoutMinutes: "",
  })

  useEffect(() => {
    if (!settings) {
      return
    }
    setForm({
      idleTimeoutMinutes: String(settings.session_idle_timeout_minutes),
      absoluteTimeoutMinutes: String(settings.session_absolute_timeout_minutes),
    })
  }, [settings])

  if (isLoading) {
    return (
      <Card className="py-0">
        <CardContent className="p-4">
          <StateMessage label="Loading security settings..." />
        </CardContent>
      </Card>
    )
  }

  if (isError || !settings) {
    return (
      <Card className="py-0">
        <CardContent className="p-4">
          <StateMessage
            label={error?.message ?? "Unable to load security settings from the backend API."}
            tone="error"
          />
        </CardContent>
      </Card>
    )
  }

  const normalizedSettings = normalizeSecuritySettingsForm(settings, form)
  const formError = securitySettingsFormError(normalizedSettings)
  const nextPeerReviewSettings = {
    ...settings,
    force_peer_review_for_status_changes: !settings.force_peer_review_for_status_changes,
  }
  const hasChanges =
    normalizedSettings.session_idle_timeout_minutes !== settings.session_idle_timeout_minutes ||
    normalizedSettings.session_absolute_timeout_minutes !==
      settings.session_absolute_timeout_minutes
  const canSave = !isSaving && hasChanges && formError === null

  return (
    <div className="space-y-3">
      <Card className="py-0">
        <CardContent className="space-y-5 p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1">
              <h2 className="text-sm font-semibold">Global Peer Review</h2>
              <p className="max-w-2xl text-sm text-muted-foreground">
                Force all finding status changes through peer review, regardless of project
                settings or individual request choices.
              </p>
            </div>
            <Badge variant={settings.force_peer_review_for_status_changes ? "default" : "outline"}>
              {settings.force_peer_review_for_status_changes ? "Enabled" : "Disabled"}
            </Badge>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={isSaving}
              onClick={() => onSave(nextPeerReviewSettings)}
              size="sm"
              type="button"
            >
              {isSaving
                ? "Saving..."
                : settings.force_peer_review_for_status_changes
                  ? "Disable force peer review"
                  : "Enable force peer review"}
            </Button>
            <Button disabled={isSaving} onClick={onRefresh} size="sm" type="button" variant="outline">
              <RefreshCw className="size-4" aria-hidden="true" />
              <span>Refresh</span>
            </Button>
          </div>
          <div className="grid gap-3 border-t pt-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">
                Max idle time (minutes)
              </span>
              <Input
                min={1}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    idleTimeoutMinutes: event.target.value,
                  }))
                }
                type="number"
                value={form.idleTimeoutMinutes}
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">
                Max session duration (minutes)
              </span>
              <Input
                min={1}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    absoluteTimeoutMinutes: event.target.value,
                  }))
                }
                type="number"
                value={form.absoluteTimeoutMinutes}
              />
            </label>
            <Button
              disabled={!canSave}
              onClick={() => onSave(normalizedSettings)}
              size="sm"
              type="button"
            >
              <ShieldCheck className="size-4" aria-hidden="true" />
              <span>{isSaving ? "Saving..." : "Save timeouts"}</span>
            </Button>
          </div>
          {formError ? (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <AlertCircle className="size-4" aria-hidden="true" />
              <span>{formError}</span>
            </div>
          ) : null}
        </CardContent>
      </Card>
      <MutationError error={mutationError} />
    </div>
  )
}

function MutationError({ error }: { error: Error | null }) {
  if (!error) {
    return null
  }

  return (
    <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <AlertCircle className="size-4" aria-hidden="true" />
      <span>{error.message}</span>
    </div>
  )
}

function AccessMetric({ label, value }: { label: string; value: number }) {
  return (
    <Card className="py-0">
      <CardContent className="p-4">
        <div className="text-xs font-medium text-muted-foreground">{label}</div>
        <div className="mt-1 text-2xl font-semibold">{new Intl.NumberFormat().format(value)}</div>
      </CardContent>
    </Card>
  )
}

function AccessGroupsCard({ access }: { access: AccessListResponse }) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="border-b px-4 py-3">
        <h2 className="text-sm font-semibold">Groups</h2>
      </div>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[42rem] border-collapse text-left text-sm">
            <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
              <tr>
                <Th>Name</Th>
                <Th>Status</Th>
                <Th>Members</Th>
              </tr>
            </thead>
            <tbody>
              {access.groups.map((group) => (
                <tr className="border-t align-top" key={group.id}>
                  <Td>
                    <div className="font-medium">{group.display_name}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{group.name}</div>
                    <div className="mt-1 break-all text-xs text-muted-foreground">{group.id}</div>
                  </Td>
                  <Td>
                    <Badge variant={group.is_protected ? "secondary" : "outline"}>
                      {group.is_protected ? "Protected" : "Custom"}
                    </Badge>
                  </Td>
                  <Td>
                    <div className="space-y-1">
                      {membershipsForGroup(access, group.id).length === 0 ? (
                        <span className="text-xs text-muted-foreground">No members</span>
                      ) : (
                        membershipsForGroup(access, group.id).map((membership) => (
                          <div
                            className="break-words text-xs text-muted-foreground"
                            key={membership.id}
                          >
                            {principalDisplayLabel(
                              access,
                              membership.principal_type,
                              membership.principal_id,
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

function AccessPrincipalsCard({ access }: { access: AccessListResponse }) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="border-b px-4 py-3">
        <h2 className="text-sm font-semibold">Principals</h2>
      </div>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[48rem] border-collapse text-left text-sm">
            <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
              <tr>
                <Th>Principal</Th>
                <Th>Type</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody>
              {access.users.map((user) => (
                <tr className="border-t align-top" key={`user-${user.id}`}>
                  <Td>
                    <div className="font-medium">{user.display_name}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{user.username}</div>
                    <div className="mt-1 break-all text-xs text-muted-foreground">{user.id}</div>
                  </Td>
                  <Td>User</Td>
                  <Td>
                    <Badge variant={user.is_active ? "default" : "secondary"}>
                      {user.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </Td>
                </tr>
              ))}
              {access.machine_credentials.map((credential) => (
                <tr className="border-t align-top" key={`machine-${credential.id}`}>
                  <Td>
                    <div className="font-medium">{credential.name}</div>
                    <div className="mt-1 break-all text-xs text-muted-foreground">
                      {credential.id}
                    </div>
                  </Td>
                  <Td>Machine</Td>
                  <Td>
                    <Badge
                      variant={
                        credential.is_active && !credential.revoked_at ? "default" : "secondary"
                      }
                    >
                      {credential.is_active && !credential.revoked_at ? "Active" : "Revoked"}
                    </Badge>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

function AccessPermissionsCard({ access }: { access: AccessListResponse }) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="border-b px-4 py-3">
        <h2 className="text-sm font-semibold">Permission Assignments</h2>
      </div>
      <CardContent className="p-0">
        {access.permission_assignments.length === 0 ? (
          <StateMessage label="No permission assignments yet." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[76rem] border-collapse text-left text-sm">
              <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
                <tr>
                  <Th>Principal</Th>
                  <Th>Effect</Th>
                  <Th>Permission</Th>
                  <Th>Scope</Th>
                  <Th>Created</Th>
                </tr>
              </thead>
              <tbody>
                {access.permission_assignments.map((assignment) => (
                  <tr className="border-t align-top" key={assignment.id}>
                    <Td>
                      <div className="font-medium">
                        {principalDisplayLabel(
                          access,
                          assignment.principal_type,
                          assignment.principal_id,
                        )}
                      </div>
                      <div className="mt-1 break-all text-xs text-muted-foreground">
                        {formatPrincipalType(assignment.principal_type)}
                      </div>
                    </Td>
                    <Td>
                      <Badge variant={assignment.effect === "allow" ? "default" : "destructive"}>
                        {assignment.effect === "allow" ? "Allow" : "Deny"}
                      </Badge>
                    </Td>
                    <Td>
                      <code className="break-all rounded-sm bg-muted px-1.5 py-0.5 text-xs">
                        {assignment.permission}
                      </code>
                    </Td>
                    <Td className="break-all text-xs text-muted-foreground">
                      {assignment.scope_type && assignment.scope_id
                        ? `${assignment.scope_type}:${assignment.scope_id}`
                        : "Unscoped"}
                    </Td>
                    <Td className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDateTime(assignment.created_at)}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function SessionsTable({
  actionSessionId,
  error,
  isActionPending,
  isError,
  isLoading,
  onRevoke,
  sessions,
}: {
  actionSessionId: string | null
  error: Error | null
  isActionPending: boolean
  isError: boolean
  isLoading: boolean
  onRevoke: (session: UserSession) => void
  sessions: UserSession[]
}) {
  if (isLoading) {
    return <StateMessage label="Loading user sessions..." />
  }

  if (isError) {
    return (
      <StateMessage
        label={error?.message ?? "Unable to load user sessions from the backend API."}
        tone="error"
      />
    )
  }

  if (sessions.length === 0) {
    return <StateMessage label="No user sessions have been created yet." />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[82rem] border-collapse text-left text-sm">
        <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
          <tr>
            <Th>User</Th>
            <Th>Status</Th>
            <Th>IP</Th>
            <Th>Last seen</Th>
            <Th>Idle expiry</Th>
            <Th>Absolute expiry</Th>
            <Th>User agent</Th>
            <Th>Actions</Th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => {
            const isThisActionPending = isActionPending && actionSessionId === session.id
            return (
              <tr
                className="border-t align-top transition-colors hover:bg-accent/60"
                key={session.id}
              >
                <Td>
                  <div className="font-medium">{session.display_name}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{session.username}</div>
                  <div className="mt-1 break-all text-xs text-muted-foreground">
                    {session.id}
                  </div>
                </Td>
                <Td>
                  <Badge variant={session.active ? "default" : "secondary"}>
                    {session.active ? "Active" : session.revoked_at ? "Revoked" : "Expired"}
                  </Badge>
                </Td>
                <Td className="break-all text-xs">{session.ip_address || "None"}</Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatDateTime(session.last_seen_at)}
                </Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatDateTime(session.idle_expires_at)}
                </Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatDateTime(session.expires_at)}
                </Td>
                <Td className="break-all text-xs text-muted-foreground">
                  {session.user_agent || "None"}
                </Td>
                <Td>
                  <Button
                    disabled={!session.active || isActionPending}
                    onClick={() => onRevoke(session)}
                    size="sm"
                    type="button"
                    variant="destructive"
                  >
                    {isThisActionPending ? "Revoking..." : "Revoke"}
                  </Button>
                </Td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function MachineCredentialsTable({
  actionCredentialId,
  credentials,
  error,
  isActionPending,
  isError,
  isLoading,
  onRegenerate,
  onRevoke,
}: {
  actionCredentialId: string | null
  credentials: MachineCredential[]
  error: Error | null
  isActionPending: boolean
  isError: boolean
  isLoading: boolean
  onRegenerate: (credential: MachineCredential) => void
  onRevoke: (credential: MachineCredential) => void
}) {
  if (isLoading) {
    return <StateMessage label="Loading machine credentials..." />
  }

  if (isError) {
    return (
      <StateMessage
        label={error?.message ?? "Unable to load machine credentials from the backend API."}
        tone="error"
      />
    )
  }

  if (credentials.length === 0) {
    return <StateMessage label="No machine credentials have been created yet." />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[76rem] border-collapse text-left text-sm">
        <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
          <tr>
            <Th>Name</Th>
            <Th>Client ID</Th>
            <Th>Status</Th>
            <Th>Created</Th>
            <Th>Updated</Th>
            <Th>Revoked</Th>
            <Th>Actions</Th>
          </tr>
        </thead>
        <tbody>
          {credentials.map((credential) => {
            const isActive = credential.is_active && !credential.revoked_at
            const isThisActionPending = isActionPending && actionCredentialId === credential.id
            return (
              <tr
                className="border-t align-top transition-colors hover:bg-accent/60"
                key={credential.id}
              >
                <Td>
                  <div className="font-medium">{credential.name}</div>
                  <div className="mt-1 break-all text-xs text-muted-foreground">
                    {credential.id}
                  </div>
                </Td>
                <Td>
                  <code className="break-all rounded-sm bg-muted px-1.5 py-0.5 text-xs">
                    {credential.client_id}
                  </code>
                </Td>
                <Td>
                  <Badge variant={isActive ? "default" : "secondary"}>
                    {isActive ? "Active" : "Revoked"}
                  </Badge>
                </Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatDateTime(credential.created_at)}
                </Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatDateTime(credential.updated_at)}
                </Td>
                <Td className="whitespace-nowrap text-xs text-muted-foreground">
                  {formatNullableDateTime(credential.revoked_at)}
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      disabled={!isActive || isActionPending}
                      onClick={() => onRegenerate(credential)}
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      {isThisActionPending ? "Working..." : "Regenerate secret"}
                    </Button>
                    <Button
                      disabled={!isActive || isActionPending}
                      onClick={() => onRevoke(credential)}
                      size="sm"
                      type="button"
                      variant="destructive"
                    >
                      {isThisActionPending ? "Working..." : "Revoke"}
                    </Button>
                  </div>
                </Td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function normalizePermissionTesterForm(
  form: PermissionTesterForm,
): PermissionTestParams {
  const scopeType = form.scopeType.trim()
  const scopeId = form.scopeId.trim()
  return {
    principal_type: form.principalType,
    principal_id: form.principalId.trim(),
    permission: form.permission.trim(),
    scope_type: scopeType && scopeId ? scopeType : null,
    scope_id: scopeType && scopeId ? scopeId : null,
  }
}

type PermissionTesterPrincipalOption = {
  id: string
  label: string
}

export function permissionTesterPrincipalOptions(
  access: AccessListResponse | null,
  principalType: PermissionTestPrincipalType,
): PermissionTesterPrincipalOption[] {
  if (!access) {
    return []
  }
  if (principalType === "user") {
    return access.users.map((user) => ({
      id: user.id,
      label: `${user.display_name} (${user.username})`,
    }))
  }
  if (principalType === "group") {
    return access.groups.map((group) => ({
      id: group.id,
      label: group.display_name,
    }))
  }
  return access.machine_credentials.map((credential) => ({
    id: credential.id,
    label: credential.name,
  }))
}

export function permissionTesterPrincipalIdForType(
  currentPrincipalId: string,
  options: PermissionTesterPrincipalOption[],
): string {
  if (options.some((option) => option.id === currentPrincipalId)) {
    return currentPrincipalId
  }
  return options[0]?.id ?? ""
}

export function permissionOptionsForAccess(access: AccessListResponse | null): string[] {
  return access?.available_permissions ?? []
}

export function normalizeSecuritySettingsForm(
  currentSettings: SecuritySettings,
  form: SecuritySettingsForm,
): SecuritySettings {
  const idleTimeoutMinutes = positiveIntegerOrFallback(
    form.idleTimeoutMinutes,
    currentSettings.session_idle_timeout_minutes,
  )
  const absoluteTimeoutMinutes = positiveIntegerOrFallback(
    form.absoluteTimeoutMinutes,
    currentSettings.session_absolute_timeout_minutes,
  )
  return {
    force_peer_review_for_status_changes:
      currentSettings.force_peer_review_for_status_changes,
    session_idle_timeout_minutes: idleTimeoutMinutes,
    session_absolute_timeout_minutes: absoluteTimeoutMinutes,
  }
}

function securitySettingsFormError(settings: SecuritySettings): string | null {
  if (settings.session_absolute_timeout_minutes < settings.session_idle_timeout_minutes) {
    return "Absolute timeout must be greater than or equal to idle timeout."
  }
  return null
}

function positiveIntegerOrFallback(value: string, fallback: number): number {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return fallback
  }
  const parsed = Number.parseInt(trimmed, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

export function normalizeAccessPermissionForm(
  form: AccessPermissionForm,
): AssignAccessPermissionParams {
  const scopeType = form.scopeType.trim()
  const scopeId = form.scopeId.trim()
  return {
    principal_type: form.principalType,
    principal_id: form.principalId.trim(),
    permission: form.permission.trim(),
    effect: form.effect,
    scope_type: scopeType && scopeId ? scopeType : null,
    scope_id: scopeType && scopeId ? scopeId : null,
  }
}

export function auditLogParams(filters: AuditLogFilters): AuditLogParams {
  const normalized = normalizeFilters(filters)
  const limit = Number.parseInt(normalized.limit, 10)
  return {
    event_type: normalized.eventType || undefined,
    created_from: normalizeDatetimeLocalForQuery(normalized.createdFrom),
    created_to: normalizeDatetimeLocalForQuery(normalized.createdTo),
    limit: Number.isFinite(limit) ? limit : undefined,
  }
}

function normalizeFilters(filters: AuditLogFilters): AuditLogFilters {
  const limit = Number.parseInt(filters.limit, 10)
  return {
    eventType: filters.eventType.trim(),
    actor: filters.actor.trim(),
    target: filters.target.trim(),
    createdFrom: filters.createdFrom.trim(),
    createdTo: filters.createdTo.trim(),
    limit: Number.isFinite(limit) && limit > 0 ? String(limit) : defaultFilters.limit,
  }
}

function normalizeDatetimeLocalForQuery(value: string): string | undefined {
  const trimmed = value.trim()
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(trimmed)) {
    return undefined
  }
  const parsed = new Date(`${trimmed}:00.000Z`)
  if (Number.isNaN(parsed.getTime()) || !parsed.toISOString().startsWith(trimmed)) {
    return undefined
  }
  return `${trimmed}:00.000Z`
}

function isDefaultFilters(filters: AuditLogFilters): boolean {
  return JSON.stringify(normalizeFilters(filters)) === JSON.stringify(defaultFilters)
}

export function filterAuditLogEvents(
  events: AuditLogEntry[],
  filters: Pick<AuditLogFilters, "actor" | "target">,
): AuditLogEntry[] {
  const actorNeedle = normalizeSearchTerm(filters.actor)
  const targetNeedle = normalizeSearchTerm(filters.target)

  if (!actorNeedle && !targetNeedle) {
    return events
  }

  return events.filter((event) => {
    const matchesActor =
      !actorNeedle ||
      matchesSearchTerm(actorNeedle, [
        event.actor_display,
        event.actor_principal_type,
        event.actor_principal_id,
      ])
    const matchesTarget =
      !targetNeedle ||
      matchesSearchTerm(targetNeedle, [
        event.target_type,
        event.target_id,
        event.project_id,
        ...metadataSearchValues(event.metadata),
      ])

    return matchesActor && matchesTarget
  })
}

function matchesSearchTerm(needle: string, values: Array<string | null | undefined>): boolean {
  return values.some((value) => normalizeSearchTerm(value ?? "").includes(needle))
}

function metadataSearchValues(metadata: Record<string, unknown>): string[] {
  return Object.values(metadata).flatMap((value) => auditSearchValues(value))
}

function membershipsForGroup(access: AccessListResponse, groupId: string) {
  return access.memberships.filter((membership) => membership.group_id === groupId)
}

function principalDisplayLabel(
  access: AccessListResponse,
  principalType: AccessPrincipalType,
  principalId: string,
): string {
  if (principalType === "user") {
    const user = access.users.find((candidate) => candidate.id === principalId)
    return user ? `${user.display_name} (${user.username})` : principalId
  }

  if (principalType === "group") {
    const group = access.groups.find((candidate) => candidate.id === principalId)
    return group ? group.display_name : principalId
  }

  const credential = access.machine_credentials.find((candidate) => candidate.id === principalId)
  return credential ? credential.name : principalId
}

function formatPrincipalType(type: string): string {
  return type
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ")
}

function auditSearchValues(value: unknown): string[] {
  if (value === null || value === undefined) {
    return []
  }

  if (Array.isArray(value)) {
    return value.flatMap((item) => auditSearchValues(item))
  }

  if (isRecord(value)) {
    return Object.values(value).flatMap((entryValue) => auditSearchValues(entryValue))
  }

  return [String(value)]
}

function normalizeSearchTerm(value: string): string {
  return value.trim().toLocaleLowerCase()
}

function Field({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
      <span>{label}</span>
      {children}
    </label>
  )
}

function PermissionOptionsDatalist({
  id,
  permissions,
}: {
  id: string
  permissions: string[]
}) {
  return (
    <datalist id={id}>
      {permissions.map((permission) => (
        <option key={permission} value={permission} />
      ))}
    </datalist>
  )
}

function Select({
  children,
  onChange,
  value,
}: {
  children: React.ReactNode
  onChange: (value: string) => void
  value: string
}) {
  return (
    <select
      className="flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
      onChange={(event) => onChange(event.target.value)}
      value={value}
    >
      {children}
    </select>
  )
}

function AuditLogTable({
  error,
  events,
  isError,
  isLoading,
}: {
  error: Error | null
  events: AuditLogEntry[]
  isError: boolean
  isLoading: boolean
}) {
  if (isLoading) {
    return <StateMessage label="Loading audit events..." />
  }

  if (isError) {
    return (
      <StateMessage
        label={error?.message ?? "Unable to load audit events from the backend API."}
        tone="error"
      />
    )
  }

  if (events.length === 0) {
    return <StateMessage label="No audit events match these filters." />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[76rem] border-collapse text-left text-sm">
        <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
          <tr>
            <Th>Timestamp</Th>
            <Th>Event type</Th>
            <Th>Actor</Th>
            <Th>Target</Th>
            <Th>IP</Th>
            <Th>Metadata</Th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr className="border-t align-top transition-colors hover:bg-accent/60" key={event.id}>
              <Td className="whitespace-nowrap text-xs text-muted-foreground">
                {formatDateTime(event.created_at)}
              </Td>
              <Td>
                <code className="break-all rounded-sm bg-muted px-1.5 py-0.5 text-xs">
                  {event.event_type}
                </code>
              </Td>
              <Td>
                <div className="font-medium">{actorLabel(event)}</div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {event.actor_principal_type || "Unknown principal"}
                </div>
              </Td>
              <Td>
                <div className="font-medium">{event.target_type || "None"}</div>
              </Td>
              <Td className="break-all text-xs">{event.ip_address || "None"}</Td>
              <Td>
                <Metadata metadata={event.metadata} targetType={event.target_type} />
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ImportHistoryTable({
  attempts,
  error,
  isError,
  isLoading,
}: {
  attempts: AdminImportAttempt[]
  error: Error | null
  isError: boolean
  isLoading: boolean
}) {
  if (isLoading) {
    return <StateMessage label="Loading import history..." />
  }

  if (isError) {
    return (
      <StateMessage
        label={error?.message ?? "Unable to load import history from the backend API."}
        tone="error"
      />
    )
  }

  if (attempts.length === 0) {
    return <StateMessage label="No import attempts have been recorded yet." />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[80rem] border-collapse text-left text-sm">
        <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
          <tr>
            <Th>Timestamp</Th>
            <Th>Status</Th>
            <Th>Project</Th>
            <Th>Asset</Th>
            <Th>Uploader</Th>
            <Th>Parser</Th>
            <Th>Message</Th>
            <Th>Metadata</Th>
          </tr>
        </thead>
        <tbody>
          {attempts.map((attempt) => (
            <tr
              className="border-t align-top transition-colors hover:bg-accent/60"
              key={attempt.id}
            >
              <Td className="whitespace-nowrap text-xs text-muted-foreground">
                {formatDateTime(attempt.created_at)}
              </Td>
              <Td>
                <Badge variant={importStatusVariant(attempt.status)}>
                  {formatPrincipalType(attempt.status)}
                </Badge>
                {attempt.correlation_id ? (
                  <div className="mt-2 break-all text-xs text-muted-foreground">
                    {attempt.correlation_id}
                  </div>
                ) : null}
              </Td>
              <Td>
                <div className="font-medium">{attempt.project_name}</div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {attempt.project_id}
                </div>
              </Td>
              <Td>
                <div className="font-medium">{attempt.asset_name || "None"}</div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {attempt.asset_path || attempt.asset_id || "No linked asset"}
                </div>
              </Td>
              <Td>
                <div className="font-medium">{importUploaderLabel(attempt)}</div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {attempt.uploader_principal_type || "Unknown principal"}
                </div>
              </Td>
              <Td>
                <code className="break-all rounded-sm bg-muted px-1.5 py-0.5 text-xs">
                  {attempt.parser_name}
                </code>
              </Td>
              <Td className="break-words text-sm">
                {attempt.sanitized_message || "No message recorded"}
              </Td>
              <Td>
                <Metadata metadata={attempt.metadata} targetType={null} />
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function StateMessage({ label, tone = "muted" }: { label: string; tone?: "error" | "muted" }) {
  return (
    <div className="flex min-h-28 items-center justify-center px-4 py-8 text-sm">
      <div
        className={
          tone === "error" ? "flex items-center gap-2 text-destructive" : "text-muted-foreground"
        }
      >
        {tone === "error" ? <AlertCircle className="size-4" aria-hidden="true" /> : null}
        <span>{label}</span>
      </div>
    </div>
  )
}

function Metadata({
  metadata,
  targetType,
}: {
  metadata: Record<string, unknown>
  targetType: string | null
}) {
  const [isExpanded, setIsExpanded] = useState(false)
  const prettyMetadata = formatAuditMetadataForDisplay(metadata, targetType)

  if (Object.keys(metadata).length === 0) {
    return <span className="text-xs text-muted-foreground">{"{}"}</span>
  }

  return (
    <div className="flex max-w-[28rem] min-w-0 flex-col items-start gap-2">
      <pre
        className={`w-full whitespace-pre-wrap break-all rounded-md bg-muted/60 p-2 font-mono text-xs leading-relaxed ${
          isExpanded ? "max-h-none overflow-visible" : "max-h-24 overflow-hidden"
        }`}
      >
        {prettyMetadata}
      </pre>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-xs text-muted-foreground"
        aria-expanded={isExpanded}
        onClick={() => setIsExpanded((current) => !current)}
      >
        {isExpanded ? (
          <ChevronUp className="size-3.5" aria-hidden="true" />
        ) : (
          <ChevronDown className="size-3.5" aria-hidden="true" />
        )}
        <span>{isExpanded ? "Collapse" : "Expand"}</span>
      </Button>
    </div>
  )
}

export function formatAuditMetadataForDisplay(
  metadata: Record<string, unknown>,
  targetType: string | null,
): string {
  return JSON.stringify(formatAuditMetadataValue(metadata, targetType), null, 2)
}

function formatAuditMetadataValue(value: unknown, targetType: string | null): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => formatAuditMetadataValue(item, targetType))
  }

  if (!isRecord(value)) {
    return value
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entryValue]) => [
      auditMetadataDisplayKey(key, targetType),
      formatAuditMetadataValue(entryValue, targetType),
    ]),
  )
}

function auditMetadataDisplayKey(key: string, targetType: string | null): string {
  if (key === "actor_principal_id") {
    return "actor_id"
  }

  if (key === "target_id" && targetType === "finding") {
    return "finding_id"
  }

  if (key === "target_id" && targetType === "machine_credential") {
    return "credential_id"
  }

  if (key === "target_id" && targetType === "session") {
    return "session_id"
  }

  return key
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}

function Td({
  children,
  className = "",
}: {
  children: React.ReactNode
  className?: string
}) {
  return <td className={`max-w-72 px-4 py-3 ${className}`}>{children}</td>
}

function actorLabel(event: AuditLogEntry): string {
  return event.actor_display || event.actor_principal_type || "Unknown actor"
}

export function importUploaderLabel(attempt: AdminImportAttempt): string {
  return (
    attempt.uploader_display ||
    attempt.uploader_principal_id ||
    attempt.uploader_principal_type ||
    "Unknown uploader"
  )
}

function importStatusVariant(status: string): "default" | "destructive" | "outline" | "secondary" {
  if (status === "success") {
    return "default"
  }
  if (status === "failed") {
    return "destructive"
  }
  return "secondary"
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value))
}

function formatNullableDateTime(value: string | null): string {
  return value ? formatDateTime(value) : "None"
}

function resultLabel(isLoading: boolean, count: number): string {
  if (isLoading) {
    return "Loading latest events"
  }
  return `${new Intl.NumberFormat().format(count)} event${count === 1 ? "" : "s"}`
}

function credentialResultLabel(isLoading: boolean, count: number): string {
  if (isLoading) {
    return "Loading credentials"
  }
  return `${new Intl.NumberFormat().format(count)} credential${count === 1 ? "" : "s"}`
}

function sessionResultLabel(isLoading: boolean, count: number): string {
  if (isLoading) {
    return "Loading sessions"
  }
  return `${new Intl.NumberFormat().format(count)} session${count === 1 ? "" : "s"}`
}

function importHistoryResultLabel(isLoading: boolean, count: number): string {
  if (isLoading) {
    return "Loading import attempts"
  }
  return `${new Intl.NumberFormat().format(count)} import attempt${count === 1 ? "" : "s"}`
}
