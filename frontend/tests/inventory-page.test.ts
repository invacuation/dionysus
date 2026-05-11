import { describe, expect, test } from "bun:test"

import {
  assetMovePayload,
  assetBadgeLabel,
  assetReferenceLabel,
  assetTypeLabel,
  assetTargetRefLabel,
  canCreateFolderForSelection,
  canMoveAssetToParent,
  assetDeleteWarning,
  createFolderPathPlaceholder,
  assetSlaOverrideLabel,
  filterAssetTree,
  filterProjects,
  normalizeGracePercent,
  projectCountLabel,
  projectDeleteWarning,
} from "../src/features/inventory/inventory-page"
import type { Asset, Project } from "../src/lib/api"
import { readFileSync } from "node:fs"
import { join } from "node:path"

function asset(overrides: Partial<Asset>): Asset {
  return {
    id: "asset-1",
    parent_id: null,
    path: "asset-1",
    type: "scan_target",
    name: "Asset 1",
    target_ref: null,
    scan_label: null,
    sla_tracking_enabled: null,
    sla_reporting_enabled: null,
    sort_order: 0,
    ...overrides,
  }
}

const rootFolder = asset({
  id: "folder-root",
  path: "root",
  type: "folder",
  name: "Root Folder",
})
const childFolder = asset({
  id: "folder-child",
  parent_id: rootFolder.id,
  path: "root/child",
  type: "folder",
  name: "Child Folder",
})
const nestedScanTarget = asset({
  id: "scan-nested",
  parent_id: childFolder.id,
  path: "root/child/api",
  type: "scan_target",
  name: "Nested API",
})
const looseScanTarget = asset({
  id: "scan-loose",
  path: "loose",
  type: "scan_target",
  name: "Loose Target",
})

function project(overrides: Partial<Project>): Project {
  return {
    id: "project-1",
    slug: "alpha",
    name: "Alpha",
    description: null,
    sla_tracking_enabled: true,
    sla_reporting_enabled: true,
    require_peer_review_for_status_changes: false,
    grace_period_enabled: false,
    grace_period_percent: 100,
    ...overrides,
  }
}

describe("canMoveAssetToParent", () => {
  test("allows moving assets to root or to folders", () => {
    const assets = [rootFolder, childFolder, nestedScanTarget, looseScanTarget]

    expect(canMoveAssetToParent(looseScanTarget, null, assets)).toBe(true)
    expect(canMoveAssetToParent(looseScanTarget, rootFolder.id, assets)).toBe(true)
  })

  test("rejects self, descendant, missing, and non-folder parents", () => {
    const assets = [rootFolder, childFolder, nestedScanTarget, looseScanTarget]

    expect(canMoveAssetToParent(rootFolder, rootFolder.id, assets)).toBe(false)
    expect(canMoveAssetToParent(rootFolder, childFolder.id, assets)).toBe(false)
    expect(canMoveAssetToParent(looseScanTarget, "missing-folder", assets)).toBe(false)
    expect(canMoveAssetToParent(rootFolder, nestedScanTarget.id, assets)).toBe(false)
  })
})

describe("assetMovePayload", () => {
  test("keeps drag move payload focused on the parent", () => {
    expect(assetMovePayload(looseScanTarget, rootFolder.id)).toEqual({
      parent_id: rootFolder.id,
    })
    expect(assetMovePayload(looseScanTarget, null)).toEqual({
      parent_id: null,
    })
  })
})

describe("assetTypeLabel", () => {
  test("presents asset type labels with UI capitalization", () => {
    expect(assetTypeLabel("folder")).toBe("Folder")
    expect(assetTypeLabel("scan_target")).toBe("Asset")
  })

  test("prefers scanner report labels for scan assets", () => {
    expect(assetBadgeLabel(asset({ scan_label: "Trivy Image Scan" }))).toBe("Trivy Image Scan")
    expect(assetBadgeLabel(asset({ type: "folder", scan_label: null }))).toBe("Folder")
  })
})

describe("assetTargetRefLabel", () => {
  test("uses N/A for folders and None for scan assets without a target reference", () => {
    expect(assetTargetRefLabel(rootFolder)).toBe("N/A")
    expect(assetTargetRefLabel(looseScanTarget)).toBe("None")
    expect(
      assetTargetRefLabel(
        asset({
          type: "scan_target",
          target_ref: "registry.example.test/api:2026.05",
        }),
      ),
    ).toBe("registry.example.test/api:2026.05")
  })

  test("uses contextual reference labels for known scan asset types", () => {
    expect(assetReferenceLabel(asset({ scan_label: "Trivy Image Scan" }))).toBe("Image")
    expect(assetReferenceLabel(asset({ scan_label: "Other Scanner" }))).toBe("Target ref")
  })
})

describe("assetSlaOverrideLabel", () => {
  test("shows explicit asset SLA overrides without inherited wording", () => {
    expect(
      assetSlaOverrideLabel(
        asset({ sla_tracking_enabled: false }),
        [rootFolder],
        project({ sla_tracking_enabled: true }),
        "tracking",
      ),
    ).toBe("Disabled")
    expect(
      assetSlaOverrideLabel(
        asset({ sla_reporting_enabled: true }),
        [rootFolder],
        project({ sla_reporting_enabled: false }),
        "reporting",
      ),
    ).toBe("Enabled")
  })

  test("shows the current inherited project SLA setting when no ancestor overrides it", () => {
    expect(
      assetSlaOverrideLabel(
        rootFolder,
        [rootFolder],
        project({ sla_tracking_enabled: true }),
        "tracking",
      ),
    ).toBe("Enabled (Inherited from Alpha)")
    expect(
      assetSlaOverrideLabel(
        rootFolder,
        [rootFolder],
        project({ sla_reporting_enabled: false }),
        "reporting",
      ),
    ).toBe("Disabled (Inherited from Alpha)")
  })

  test("shows the current inherited ancestor SLA setting when a parent overrides it", () => {
    const parent = asset({
      id: "parent-folder",
      type: "folder",
      name: "ipsum",
      sla_tracking_enabled: false,
    })
    const child = asset({
      id: "child-asset",
      parent_id: parent.id,
      sla_tracking_enabled: null,
    })

    expect(
      assetSlaOverrideLabel(child, [parent, child], project({ sla_tracking_enabled: true }), "tracking"),
    ).toBe("Disabled (Inherited from ipsum)")
  })
})

describe("filterProjects", () => {
  test("matches project name, slug, and description case-insensitively", () => {
    const projects = [
      project({ id: "alpha", slug: "alpha", name: "Alpha", description: "Mobile estate" }),
      project({ id: "beta", slug: "payments", name: "Billing", description: "PCI APIs" }),
      project({ id: "gamma", slug: "gamma", name: "Gamma", description: null }),
    ]

    expect(filterProjects(projects, "MOBILE").map((item) => item.id)).toEqual(["alpha"])
    expect(filterProjects(projects, "pay").map((item) => item.id)).toEqual(["beta"])
    expect(filterProjects(projects, "pci").map((item) => item.id)).toEqual(["beta"])
    expect(filterProjects(projects, " ").map((item) => item.id)).toEqual([
      "alpha",
      "beta",
      "gamma",
    ])
  })
})

describe("projectCountLabel", () => {
  test("uses singular and plural project labels", () => {
    expect(projectCountLabel(1)).toBe("1 project")
    expect(projectCountLabel(2)).toBe("2 projects")
  })
})

describe("normalizeGracePercent", () => {
  test("keeps positive integer grace percentages and falls back for invalid values", () => {
    expect(normalizeGracePercent(" 70 ", 100)).toBe(70)
    expect(normalizeGracePercent("0", 100)).toBe(100)
    expect(normalizeGracePercent("not numeric", 80)).toBe(80)
  })
})

describe("project grace percentage UI", () => {
  test("keeps the grace percentage value on one line", () => {
    const source = readFileSync(
      join(import.meta.dir, "../src/features/inventory/inventory-page.tsx"),
      "utf8",
    )

    expect(source).toContain('className="whitespace-nowrap">{project.grace_period_percent}%')
  })
})

describe("filterAssetTree", () => {
  test("matches asset fields and keeps ancestor folders for context", () => {
    const releaseTarget = asset({
      id: "release-target",
      parent_id: childFolder.id,
      path: "root/child/api",
      type: "scan_target",
      name: "Release API",
      target_ref: "registry.example.test/release-api:2026.05",
    })
    const assets = [rootFolder, childFolder, releaseTarget, looseScanTarget]

    expect(filterAssetTree(assets, "release-api").map((item) => item.id)).toEqual([
      rootFolder.id,
      childFolder.id,
      releaseTarget.id,
    ])
    expect(filterAssetTree(assets, "scan_target").map((item) => item.id)).toEqual([
      rootFolder.id,
      childFolder.id,
      releaseTarget.id,
      looseScanTarget.id,
    ])
  })
})

describe("delete confirmation text", () => {
  test("warns project deletion cascades through dependent inventory and finding data", () => {
    expect(projectDeleteWarning(project({ slug: "alpha", name: "Alpha" }))).toContain(
      "folders, assets, scans, imports, findings, comments, workflow, and history tied to this project",
    )
  })

  test("warns asset deletion cascades through descendants and tied scan data", () => {
    expect(assetDeleteWarning(rootFolder)).toContain(
      "selected node, descendants, scans, imports, and findings tied to them",
    )
  })
})

describe("inventory creation UI", () => {
  test("suggests new folder paths under the selected folder", () => {
    const assets = [rootFolder, childFolder, nestedScanTarget, looseScanTarget]

    expect(createFolderPathPlaceholder(rootFolder, assets)).toBe("root/new_folder")
    expect(createFolderPathPlaceholder(childFolder, assets)).toBe("root/child/new_folder")
    expect(createFolderPathPlaceholder(nestedScanTarget, assets)).toBe("root/child/new_folder")
    expect(createFolderPathPlaceholder(looseScanTarget, assets)).toBe("new_folder")
    expect(createFolderPathPlaceholder(null, assets)).toBe("new_folder")
  })

  test("only enables folder creation for root or selected folders", () => {
    expect(canCreateFolderForSelection("", null)).toBe(false)
    expect(canCreateFolderForSelection("project-1", null)).toBe(true)
    expect(canCreateFolderForSelection("project-1", rootFolder)).toBe(true)
    expect(canCreateFolderForSelection("project-1", nestedScanTarget)).toBe(false)
  })

  test("does not expose a manual asset or scan target creation form", () => {
    const source = readFileSync(
      join(import.meta.dir, "../src/features/inventory/inventory-page.tsx"),
      "utf8",
    )

    expect(source).not.toContain("Create Asset")
    expect(source).not.toContain("Create asset")
    expect(source).not.toContain("createScanTarget")
  })

  test("exposes project and folder creation through compact add buttons", () => {
    const source = readFileSync(
      join(import.meta.dir, "../src/features/inventory/inventory-page.tsx"),
      "utf8",
    )

    expect(source).toContain('aria-label="Add project"')
    expect(source).toContain('aria-label="Add folder"')
    expect(source).toContain("isCreateProjectOpen ?")
    expect(source).toContain("isCreateFolderOpen ?")
  })

  test("keeps internal ordering and parent moves out of the edit form", () => {
    const source = readFileSync(
      join(import.meta.dir, "../src/features/inventory/inventory-page.tsx"),
      "utf8",
    )

    expect(source).not.toContain('<DetailRow label="Sort order">')
    expect(source).not.toContain('<label className="grid gap-1 text-xs font-medium text-muted-foreground">\n          Parent')
  })
})
