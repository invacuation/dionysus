import { expect, test } from "@playwright/test"
import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const realBackendEnabled = process.env.E2E_REAL_BACKEND === "1"
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..")
const trivyFixture = resolve(repositoryRoot, "python/tests/fixtures/trivy-image.json")

test.skip(!realBackendEnabled, "deployed backend e2e runs only against a real app server")

test("signs in to the deployed Go-backed app and exercises the core API workflow", async ({
  page,
}) => {
  await page.goto("/")

  await page.getByLabel("Username").fill("admin")
  await page.getByLabel("Password").fill("change-me-now-please")
  await page.getByRole("button", { name: "Sign in" }).click()

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible()
  await expect(page.getByText("Local Admin")).toBeVisible()

  await page.getByRole("link", { name: "Inventory" }).click()
  await expect(page).toHaveURL("/inventory")
  await expect(page.getByRole("heading", { name: "Asset Inventory" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Add project" })).toBeVisible()

  await page.getByRole("link", { name: "Findings" }).click()
  await expect(page).toHaveURL("/findings")
  await expect(page.getByRole("heading", { level: 1, name: "Findings" })).toBeVisible()

  await page.getByRole("link", { name: "Import Scans" }).click()
  await expect(page).toHaveURL("/imports")
  await expect(page.getByRole("heading", { name: "Import Scans" })).toBeVisible()

  await page.getByRole("link", { name: "Admin" }).click()
  await expect(page).toHaveURL("/admin")
  await expect(page.getByRole("heading", { name: "Admin" })).toBeVisible()

  const suffix = Date.now().toString(36)
  const projectResponse = await page.request.post("/api/projects", {
    data: {
      slug: `deployed-${suffix}`,
      name: `Deployed Smoke ${suffix}`,
      description: "Created by deployed app e2e.",
      sla_tracking_enabled: false,
      sla_reporting_enabled: false,
      require_peer_review_for_status_changes: false,
      grace_period_enabled: true,
      grace_period_percent: 50,
    },
  })
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string }

  const targetResponse = await page.request.post(`/api/projects/${project.id}/scan-targets`, {
    data: {
      folder_path: "images/releases",
      name: "Production Image",
      target_ref: "registry.example.test/dionysus/api:2026.05.07",
    },
  })
  expect(targetResponse.ok()).toBeTruthy()
  const target = (await targetResponse.json()) as { id: string }

  const importResponse = await page.request.post("/api/imports/trivy", {
    multipart: {
      project_id: project.id,
      scan_target_id: target.id,
      scan_started_at: "2026-05-07T09:30:00+00:00",
      report_file: {
        name: "trivy-image.json",
        mimeType: "application/json",
        buffer: readFileSync(trivyFixture),
      },
    },
  })
  expect(importResponse.ok()).toBeTruthy()
  await expect(importResponse.json()).resolves.toMatchObject({
    finding_count: 2,
    group_count: 2,
    project_id: project.id,
    scan_target_id: target.id,
  })

  const findingsResponse = await page.request.get(`/api/findings?project_id=${project.id}`)
  expect(findingsResponse.ok()).toBeTruthy()
  await expect(findingsResponse.json()).resolves.toMatchObject({
    rows: expect.arrayContaining([
      expect.objectContaining({ primary_identifier: "CVE-2026-1001" }),
      expect.objectContaining({ primary_identifier: "CVE-2026-2002" }),
    ]),
  })

  await page.goto(`/findings?project_id=${project.id}`)
  await expect(page.getByRole("heading", { level: 1, name: "Findings" })).toBeVisible()
  await expect(page.getByText("CVE-2026-1001")).toBeVisible()
})
