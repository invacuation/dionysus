import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import {
  defaultFindingFilters,
  filterScopeAssets,
  filterScopeProjects,
  findingInventoryBrowserRows,
  findingFiltersFromSearchParams,
  findingInventoryScopeFromSearchParams,
  findingParams,
  inventoryScopeLabel,
  type FindingInventoryScope,
} from "../src/features/findings/findings-page"
import type { Asset, Project } from "../src/lib/api"

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

function asset(overrides: Partial<Asset>): Asset {
  return {
    id: "asset-1",
    parent_id: null,
    path: "root/api",
    type: "scan_target",
    name: "API",
    target_ref: "registry.example.test/api:latest",
    scan_label: "Trivy Image Scan",
    sla_tracking_enabled: null,
    sla_reporting_enabled: null,
    sort_order: 0,
    ...overrides,
  }
}

describe("findingParams", () => {
  test("adds selected project and asset scope to normal filters", () => {
    const projectScope: FindingInventoryScope = { assetId: "", projectId: "project-1" }
    const assetScope: FindingInventoryScope = { assetId: "asset-1", projectId: "project-1" }

    expect(findingParams(defaultFindingFilters, projectScope)).toMatchObject({
      project_id: "project-1",
    })
    expect(findingParams(defaultFindingFilters, assetScope)).toMatchObject({
      asset_id: "asset-1",
      project_id: "project-1",
    })
  })
})

describe("findings URL parameters", () => {
  test("accepts only known filter values from URL search params", () => {
    const filters = findingFiltersFromSearchParams(
      new URLSearchParams(
        "severity=critical&status=open&fix_available=true&sort=severity&direction=asc&identifier=CVE-2026&package=openssl",
      ),
    )

    expect(filters).toMatchObject({
      severity: "CRITICAL",
      status: "open",
      fixAvailable: "true",
      sort: "severity",
      direction: "asc",
      identifier: "CVE-2026",
      packageName: "openssl",
    })
  })

  test("ignores invalid URL values before calling the backend", () => {
    const filters = findingFiltersFromSearchParams(
      new URLSearchParams("severity=<script>&status=missing&sort=bad&direction=sideways"),
    )
    const scope = findingInventoryScopeFromSearchParams(
      new URLSearchParams("project_id=project-1&asset_id=../etc/passwd"),
    )

    expect(filters).toEqual(defaultFindingFilters)
    expect(scope).toEqual({ projectId: "project-1", assetId: "" })
  })
})

describe("inventoryScopeLabel", () => {
  test("summarizes entire inventory, project, and selected asset scopes", () => {
    const alpha = project({ name: "Alpha", slug: "alpha" })
    const api = asset({ name: "API", path: "root/api" })

    expect(inventoryScopeLabel({ assetId: "", projectId: "" }, [alpha], [])).toBe(
      "Entire inventory",
    )
    expect(inventoryScopeLabel({ assetId: "", projectId: alpha.id }, [alpha], [api])).toBe(
      "Alpha",
    )
    expect(inventoryScopeLabel({ assetId: api.id, projectId: alpha.id }, [alpha], [api])).toBe(
      "Alpha / API",
    )
  })

  test("uses asset ancestor names rather than raw paths for selected scope labels", () => {
    const alpha = project({ name: "Alpha", slug: "alpha" })
    const ubuntu = asset({
      id: "ubuntu",
      name: "ubuntu",
      path: "ubuntu",
      type: "folder",
      target_ref: null,
      scan_label: null,
    })
    const release = asset({
      id: "release",
      parent_id: ubuntu.id,
      name: "25.10",
      path: "ubuntu/25.10",
      type: "folder",
      target_ref: null,
      scan_label: null,
    })
    const image = asset({
      id: "image",
      parent_id: release.id,
      name: "ubuntu:25.10",
      path: "ubuntu/25.10/ubuntu:25.10",
    })

    expect(
      inventoryScopeLabel({ assetId: image.id, projectId: alpha.id }, [alpha], [
        ubuntu,
        release,
        image,
      ]),
    ).toBe("Alpha / ubuntu / 25.10 / ubuntu:25.10")
  })
})

describe("finding inventory tree helpers", () => {
  test("filters projects by name, slug, and description", () => {
    const alpha = project({
      id: "alpha",
      name: "Alpha API",
      slug: "alpha-api",
      description: "Customer facing services",
    })
    const beta = project({
      id: "beta",
      name: "Beta Worker",
      slug: "beta-worker",
      description: "Batch pipeline",
    })

    expect(filterScopeProjects([alpha, beta], "customer").map((item) => item.id)).toEqual([
      alpha.id,
    ])
    expect(filterScopeProjects([alpha, beta], "worker").map((item) => item.id)).toEqual([
      beta.id,
    ])
  })

  test("keeps ancestor folders when filtering asset scope search results", () => {
    const root = asset({
      id: "folder-root",
      name: "ubuntu",
      path: "ubuntu",
      type: "folder",
      target_ref: null,
      scan_label: null,
      sort_order: 0,
    })
    const release = asset({
      id: "folder-release",
      parent_id: root.id,
      name: "25.10",
      path: "ubuntu/25.10",
      type: "folder",
      target_ref: null,
      scan_label: null,
      sort_order: 0,
    })
    const image = asset({
      id: "image",
      parent_id: release.id,
      name: "ubuntu:25.10",
      path: "ubuntu/25.10/ubuntu:25.10",
      target_ref: "registry.example.test/ubuntu:25.10",
      sort_order: 0,
    })
    const docs = asset({
      id: "docs",
      name: "docs",
      path: "docs",
      target_ref: "registry.example.test/docs:latest",
      sort_order: 1,
    })

    expect(filterScopeAssets([root, release, image, docs], "25.10").map((item) => item.id)).toEqual(
      [root.id, release.id, image.id],
    )
  })

  test("shows direct children for the current folder in the inventory browser", () => {
    const folder = asset({
      id: "folder",
      name: "images",
      path: "images",
      type: "folder",
      target_ref: null,
      scan_label: null,
      sort_order: 0,
    })
    const image = asset({
      id: "image",
      parent_id: folder.id,
      name: "api",
      path: "images/api",
      sort_order: 0,
    })
    const nested = asset({
      id: "nested",
      parent_id: image.id,
      name: "nested",
      path: "images/api/nested",
      sort_order: 0,
    })

    expect(
      findingInventoryBrowserRows([folder, image, nested], "", "").map((row) =>
        row.kind === "asset" ? row.asset.id : row.id,
      ),
    ).toEqual(["folder"])
    expect(
      findingInventoryBrowserRows([folder, image, nested], "", folder.id).map((row) =>
        row.kind === "asset" ? row.asset.id : row.id,
      ),
    ).toEqual([`up:${folder.id}`, "image"])
  })
})

describe("findings page labels", () => {
  test("uses Findings rather than verbose alternatives in the primary UI labels", () => {
    const pageSource = readFileSync(
      join(import.meta.dir, "../src/features/findings/findings-page.tsx"),
      "utf8",
    )
    const shellSource = readFileSync(join(import.meta.dir, "../src/components/app-shell.tsx"), "utf8")

    expect(pageSource).not.toContain("All Findings")
    expect(pageSource).not.toContain("Finding Results")
    expect(shellSource).not.toContain("All Findings")
  })
})
