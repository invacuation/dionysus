import { describe, expect, test } from "bun:test"

import {
  actorLabel,
  actorPrincipalLabel,
  auditLogParams,
  defaultAdminSortState,
  filterAuditLogEvents,
  formatAuditMetadataForDisplay,
  importUploaderLabel,
  nextAdminSortState,
  normalizeAccessPermissionForm,
  normalizePermissionTesterForm,
  permissionOptionsForAccess,
  principalOptionsForAccess,
  searchPrincipalOptions,
  permissionTesterPrincipalOptions,
  normalizeSecuritySettingsForm,
  scopeOptionsForAccess,
} from "../src/features/admin/admin-page"
import type { AccessListResponse, AdminImportAttempt, AuditLogEntry } from "../src/lib/api"

const baseEvent: AuditLogEntry = {
  id: "audit-1",
  event_type: "finding.status.changed",
  actor_principal_type: "user",
  actor_principal_id: "alice-id",
  actor_display: "Alice Admin",
  target_type: "finding",
  target_id: "finding-1",
  project_id: "project-1",
  ip_address: "127.0.0.1",
  user_agent: "test-agent",
  metadata: { status_to: "fixed", note: "release blocker" },
  created_at: "2026-05-08T12:00:00Z",
}

const baseImportAttempt: AdminImportAttempt = {
  id: "attempt-1",
  project_id: "project-1",
  project_name: "Alpha",
  asset_id: "asset-1",
  asset_name: "API Image",
  asset_path: "images/api",
  uploader_principal_type: "user",
  uploader_principal_id: "user-1",
  uploader_display: "Alice Admin",
  status: "failed",
  parser_name: "trivy-image-json",
  sanitized_message: "Invalid JSON report",
  correlation_id: "corr-1",
  metadata: { failure_category: "parser_error", raw_report_retained: false },
  created_at: "2026-05-08T12:00:00Z",
  updated_at: "2026-05-08T12:01:00Z",
}

const accessList: AccessListResponse = {
  users: [
    {
      id: "user-1",
      username: "alice",
      display_name: "Alice Admin",
      is_active: true,
      created_at: "2026-05-08T12:00:00Z",
      updated_at: "2026-05-08T12:00:00Z",
    },
  ],
  machine_credentials: [
    {
      id: "credential-1",
      name: "ci-runner",
      client_id: "client-1",
      is_active: true,
      created_by_principal_type: "user",
      created_by_principal_id: "user-1",
      created_by_display: "Alice Admin",
      created_at: "2026-05-08T12:00:00Z",
      updated_at: "2026-05-08T12:00:00Z",
      revoked_at: null,
    },
  ],
  groups: [
    {
      id: "group-1",
      name: "security",
      display_name: "Security",
      is_protected: false,
      created_at: "2026-05-08T12:00:00Z",
      updated_at: "2026-05-08T12:00:00Z",
    },
  ],
  memberships: [],
  permission_assignments: [],
  available_permissions: ["finding:view", "import:upload"],
}

describe("filterAuditLogEvents", () => {
  test("filters by actor display, principal type, and principal id", () => {
    const events = [
      baseEvent,
      {
        ...baseEvent,
        id: "audit-2",
        actor_display: "Machine Credential",
        actor_principal_type: "machine",
        actor_principal_id: "credential-1",
      },
    ]

    expect(filterAuditLogEvents(events, { actor: "alice", target: "" })).toEqual([baseEvent])
    expect(filterAuditLogEvents(events, { actor: "machine", target: "" })).toEqual([events[1]])
    expect(filterAuditLogEvents(events, { actor: "credential-1", target: "" })).toEqual([
      events[1],
    ])
  })

  test("filters by target fields and metadata values", () => {
    const events = [
      baseEvent,
      {
        ...baseEvent,
        id: "audit-2",
        target_type: "asset",
        target_id: "asset-1",
        project_id: "project-2",
        metadata: { import_source: "manual-upload" },
      },
    ]

    expect(filterAuditLogEvents(events, { actor: "", target: "finding-1" })).toEqual([baseEvent])
    expect(filterAuditLogEvents(events, { actor: "", target: "project-2" })).toEqual([events[1]])
    expect(filterAuditLogEvents(events, { actor: "", target: "manual-upload" })).toEqual([
      events[1],
    ])
  })
})

describe("principalOptionsForAccess", () => {
  test("uses display names for access assignment controls", () => {
    expect(principalOptionsForAccess(accessList, "user")).toEqual([
      { id: "user-1", label: "Alice Admin (alice)" },
    ])
    expect(principalOptionsForAccess(accessList, "machine")).toEqual([
      { id: "credential-1", label: "ci-runner" },
    ])
    expect(principalOptionsForAccess(accessList, "group")).toEqual([
      { id: "group-1", label: "Security" },
    ])
  })
})

describe("searchPrincipalOptions", () => {
  test("filters typeahead principal matches by display labels", () => {
    const options = principalOptionsForAccess(accessList, "user")

    expect(searchPrincipalOptions(options, "alice")).toEqual(options)
    expect(searchPrincipalOptions(options, "admin")).toEqual(options)
    expect(searchPrincipalOptions(options, "missing")).toEqual([])
  })
})

describe("scopeOptionsForAccess", () => {
  test("always offers unscoped and project scope types without raw UUID wording", () => {
    expect(scopeOptionsForAccess()).toEqual([
      { label: "Unscoped", scopeType: "", value: "" },
      { label: "Project", scopeType: "project", value: "project" },
    ])
  })
})

describe("nextAdminSortState", () => {
  test("activates a new column and toggles direction on repeat clicks", () => {
    const initial = defaultAdminSortState("name")

    expect(nextAdminSortState(initial, "type")).toEqual({ column: "type", direction: "asc" })
    expect(nextAdminSortState({ column: "type", direction: "asc" }, "type")).toEqual({
      column: "type",
      direction: "desc",
    })
  })
})

describe("auditLogParams", () => {
  test("trims server-side audit filters and normalizes datetime-local ranges to UTC ISO strings", () => {
    expect(
      auditLogParams({
        eventType: " finding.status.changed ",
        actor: " Alice ",
        target: " finding-1 ",
        createdFrom: "2026-05-08T12:30",
        createdTo: "2026-05-08T14:45",
        limit: " 25 ",
      }),
    ).toEqual({
      event_type: "finding.status.changed",
      created_from: "2026-05-08T12:30:00.000Z",
      created_to: "2026-05-08T14:45:00.000Z",
      limit: 25,
    })
  })

  test("omits blank and invalid datetime-local range values", () => {
    expect(
      auditLogParams({
        eventType: "",
        actor: "",
        target: "",
        createdFrom: "2026-02-31T12:00",
        createdTo: "",
        limit: "0",
      }),
    ).toEqual({ limit: 50 })
  })
})

describe("audit login failure labels", () => {
  test("uses N/A when a failed login has no actor or principal", () => {
    const event = {
      ...baseEvent,
      event_type: "auth.login.failure",
      actor_display: null,
      actor_principal_type: null,
      actor_principal_id: null,
    }

    expect(actorLabel(event)).toBe("N/A")
    expect(actorPrincipalLabel(event)).toBe("N/A")
  })

  test("keeps unknown wording for non-login-failure events without actor details", () => {
    const event = {
      ...baseEvent,
      actor_display: null,
      actor_principal_type: null,
      actor_principal_id: null,
    }

    expect(actorLabel(event)).toBe("Unknown actor")
    expect(actorPrincipalLabel(event)).toBe("Unknown principal")
  })
})

describe("normalizeAccessPermissionForm", () => {
  test("trims permission assignment values and keeps complete scopes", () => {
    expect(
      normalizeAccessPermissionForm({
        principalType: "group",
        principalId: " Security ",
        permission: " import:upload ",
        effect: "allow",
        scopeType: " project ",
        scopeId: " Alpha ",
      }, [
        { id: "project-1", slug: "alpha", name: "Alpha", description: null, sla_tracking_enabled: true, sla_reporting_enabled: true, require_peer_review_for_status_changes: false, grace_period_enabled: false, grace_period_percent: 100, critical_sla_days: 30, high_sla_days: 60, medium_sla_days: 90, low_sla_days: 180, unknown_sla_days: 365, created_at: "2026-05-08T12:00:00Z", updated_at: "2026-05-08T12:00:00Z" }],
        principalOptionsForAccess(accessList, "group"),
      ),
    ).toEqual({
      principal_type: "group",
      principal_id: "group-1",
      permission: "import:upload",
      effect: "allow",
      scope_type: "project",
      scope_id: "project-1",
    })
  })

  test("assigns unscoped permissions when scope fields are incomplete", () => {
    expect(
      normalizeAccessPermissionForm({
        principalType: "user",
        principalId: "user-1",
        permission: "admin:*",
        effect: "deny",
        scopeType: "project",
        scopeId: "",
      }),
    ).toEqual({
      principal_type: "user",
      principal_id: "user-1",
      permission: "admin:*",
      effect: "deny",
      scope_type: null,
      scope_id: null,
    })
  })

  test("does not resolve duplicate principal labels to the first matching id", () => {
    expect(
      normalizeAccessPermissionForm(
        {
          principalType: "group",
          principalId: "Security",
          permission: "import:upload",
          effect: "allow",
          scopeType: "",
          scopeId: "",
        },
        [],
        [
          { id: "group-1", label: "Security" },
          { id: "group-2", label: "Security" },
        ],
      ),
    ).toMatchObject({
      principal_id: "Security",
    })
  })

  test("does not resolve duplicate project names to the first matching scope id", () => {
    const duplicateProjects = [
      {
        id: "project-1",
        slug: "alpha-1",
        name: "Alpha",
        description: null,
        sla_tracking_enabled: true,
        sla_reporting_enabled: true,
        require_peer_review_for_status_changes: false,
        grace_period_enabled: false,
        grace_period_percent: 100,
        critical_sla_days: 30,
        high_sla_days: 60,
        medium_sla_days: 90,
        low_sla_days: 180,
        unknown_sla_days: 365,
        created_at: "2026-05-08T12:00:00Z",
        updated_at: "2026-05-08T12:00:00Z",
      },
      {
        id: "project-2",
        slug: "alpha-2",
        name: "Alpha",
        description: null,
        sla_tracking_enabled: true,
        sla_reporting_enabled: true,
        require_peer_review_for_status_changes: false,
        grace_period_enabled: false,
        grace_period_percent: 100,
        critical_sla_days: 30,
        high_sla_days: 60,
        medium_sla_days: 90,
        low_sla_days: 180,
        unknown_sla_days: 365,
        created_at: "2026-05-08T12:00:00Z",
        updated_at: "2026-05-08T12:00:00Z",
      },
    ]

    expect(
      normalizeAccessPermissionForm(
        {
          principalType: "group",
          principalId: "group-1",
          permission: "import:upload",
          effect: "allow",
          scopeType: "project",
          scopeId: "Alpha",
        },
        duplicateProjects,
      ),
    ).toMatchObject({
      scope_id: "Alpha",
    })
  })
})

describe("importUploaderLabel", () => {
  test("prefers the resolved uploader display name", () => {
    expect(importUploaderLabel(baseImportAttempt)).toBe("Alice Admin")
  })

  test("falls back through principal id, principal type, and unknown label", () => {
    expect(importUploaderLabel({ ...baseImportAttempt, uploader_display: null })).toBe("user-1")
    expect(
      importUploaderLabel({
        ...baseImportAttempt,
        uploader_display: null,
        uploader_principal_id: null,
      }),
    ).toBe("user")
    expect(
      importUploaderLabel({
        ...baseImportAttempt,
        uploader_display: null,
        uploader_principal_id: null,
        uploader_principal_type: null,
      }),
    ).toBe("Unknown uploader")
  })
})

describe("formatAuditMetadataForDisplay", () => {
  test("labels finding target ids as finding ids", () => {
    expect(
      formatAuditMetadataForDisplay(
        { target_id: "finding-1", actor_principal_id: "alice-id" },
        "finding",
      ),
    ).toContain('"finding_id": "finding-1"')
  })

  test("labels machine credential target ids as credential ids", () => {
    expect(
      formatAuditMetadataForDisplay(
        { target_id: "credential-1", actor_principal_id: "alice-id" },
        "machine_credential",
      ),
    ).toContain('"credential_id": "credential-1"')
  })

  test("labels session target ids as session ids", () => {
    expect(
      formatAuditMetadataForDisplay(
        { target_id: "session-1", actor_principal_id: "alice-id" },
        "session",
      ),
    ).toContain('"session_id": "session-1"')
  })
})

describe("normalizePermissionTesterForm", () => {
  test("trims permission tester values and keeps complete scope pairs", () => {
    expect(
      normalizePermissionTesterForm({
        principalType: "user",
        principalId: " Alice Admin (alice) ",
        permission: " finding:view ",
        scopeType: " project ",
        scopeId: " Alpha ",
      }, [
        { id: "project-1", slug: "alpha", name: "Alpha", description: null, sla_tracking_enabled: true, sla_reporting_enabled: true, require_peer_review_for_status_changes: false, grace_period_enabled: false, grace_period_percent: 100, critical_sla_days: 30, high_sla_days: 60, medium_sla_days: 90, low_sla_days: 180, unknown_sla_days: 365, created_at: "2026-05-08T12:00:00Z", updated_at: "2026-05-08T12:00:00Z" }],
        principalOptionsForAccess(accessList, "user"),
      ),
    ).toEqual({
      principal_type: "user",
      principal_id: "user-1",
      permission: "finding:view",
      scope_type: "project",
      scope_id: "project-1",
    })
  })

  test("sends unscoped checks when the scope pair is incomplete", () => {
    expect(
      normalizePermissionTesterForm({
        principalType: "machine",
        principalId: "credential-1",
        permission: "report:upload",
        scopeType: "project",
        scopeId: "",
      }),
    ).toEqual({
      principal_type: "machine",
      principal_id: "credential-1",
      permission: "report:upload",
      scope_type: null,
      scope_id: null,
    })
  })
})

describe("permission tester principal selection", () => {
  test("builds principal options from the selected principal type", () => {
    expect(permissionTesterPrincipalOptions(accessList, "user")).toEqual([
      { id: "user-1", label: "Alice Admin (alice)" },
    ])
    expect(permissionTesterPrincipalOptions(accessList, "machine")).toEqual([
      { id: "credential-1", label: "ci-runner" },
    ])
    expect(permissionTesterPrincipalOptions(accessList, "group")).toEqual([
      { id: "group-1", label: "Security" },
    ])
  })
})

describe("permissionOptionsForAccess", () => {
  test("uses backend-provided permissions for filterable permission controls", () => {
    expect(permissionOptionsForAccess(accessList)).toEqual(["finding:view", "import:upload"])
    expect(permissionOptionsForAccess(null)).toEqual([])
  })
})

describe("normalizeSecuritySettingsForm", () => {
  test("trims numeric session timeout fields", () => {
    expect(
      normalizeSecuritySettingsForm(
        {
          force_peer_review_for_status_changes: false,
          session_idle_timeout_minutes: 30,
          session_absolute_timeout_minutes: 480,
        },
        {
          idleTimeoutMinutes: " 45 ",
          absoluteTimeoutMinutes: " 720 ",
        },
      ),
    ).toEqual({
      force_peer_review_for_status_changes: false,
      session_idle_timeout_minutes: 45,
      session_absolute_timeout_minutes: 720,
    })
  })

  test("falls back to current settings when numeric form values are invalid", () => {
    expect(
      normalizeSecuritySettingsForm(
        {
          force_peer_review_for_status_changes: true,
          session_idle_timeout_minutes: 30,
          session_absolute_timeout_minutes: 480,
        },
        {
          idleTimeoutMinutes: "0",
          absoluteTimeoutMinutes: "not a number",
        },
      ),
    ).toEqual({
      force_peer_review_for_status_changes: true,
      session_idle_timeout_minutes: 30,
      session_absolute_timeout_minutes: 480,
    })
  })
})

describe("security settings timeout copy", () => {
  test("uses plain session timeout labels", async () => {
    const { readFile } = await import("node:fs/promises")
    const { join } = await import("node:path")
    const source = await readFile(
      join(import.meta.dir, "../src/features/admin/admin-page.tsx"),
      "utf8",
    )

    expect(source).toContain("Max idle time (minutes)")
    expect(source).toContain("Max session duration (minutes)")
    expect(source).not.toContain("Idle timeout minutes")
    expect(source).not.toContain("Absolute timeout minutes")
  })
})

describe("machine credential token revocation UI", () => {
  test("does not expose configurable token revocation copy", async () => {
    const { readFile } = await import("node:fs/promises")
    const { join } = await import("node:path")
    const source = await readFile(
      join(import.meta.dir, "../src/features/admin/admin-page.tsx"),
      "utf8",
    )

    expect(source).toContain("revokeMachineCredential(credentialId, { revoke_tokens: true })")
    expect(source).toContain(
      "regenerateMachineCredentialSecret(credentialId, { revoke_tokens: true })",
    )
    expect(source).not.toContain("Revoke active tokens for this credential")
    expect(source).not.toContain("Applies when regenerating a secret or revoking a credential.")
    expect(source).not.toContain("Revoke existing tokens")
  })

  test("does not show a standalone refresh button and keeps the secret panel dark-mode friendly", async () => {
    const { readFile } = await import("node:fs/promises")
    const { join } = await import("node:path")
    const source = await readFile(
      join(import.meta.dir, "../src/features/admin/admin-page.tsx"),
      "utf8",
    )

    expect(source).not.toContain("Refresh machine credential list")
    expect(source).not.toContain("bg-amber-50")
    expect(source).not.toContain("text-amber-950")
  })
})
