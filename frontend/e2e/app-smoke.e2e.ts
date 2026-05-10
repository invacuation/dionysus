import { expect, test, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => {
  await mockAuthenticatedApi(page)
})

test("renders the authenticated workspace and inventory scan labels", async ({ page }) => {
  await page.goto("/")

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible()
  await expect(page.getByText(/^v\d+\.\d+\.\d+$/)).toBeVisible()

  await page.getByRole("link", { name: "Findings" }).click()
  await expect(page).toHaveURL("/findings")
  await expect(page.getByRole("heading", { level: 1, name: "Findings" })).toBeVisible()
  await expect(page.getByText("Inventory", { exact: true }).first()).toBeVisible()

  await page.getByRole("link", { name: "Inventory" }).click()

  await expect(page).toHaveURL("/inventory")
  await expect(page.getByRole("heading", { name: "Asset Inventory" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Add project" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Add folder" })).toBeVisible()
  await expect(page.getByText("Folder").first()).toBeVisible()
  await expect(page.getByText("Trivy Image Scan")).toBeVisible()
})

async function mockAuthenticatedApi(page: Page): Promise<void> {
  await page.route("**/api/auth/me", async (route) => {
    await route.fulfill({
      json: {
        actor_type: "user",
        actor_id: "user-1",
        display_name: "Codex Dev",
        principal_type: "user",
        principal_id: "user-1",
        auth_method: "session",
        session_id: "session-1",
        machine_token_id: null,
        mixed_credentials_present: false,
      },
    })
  })

  await page.route("**/api/overview", async (route) => {
    await route.fulfill({
      json: {
        open_findings: 1,
        overdue_sla: 0,
        grace_period_risk: 0,
        severity_counts: [{ severity: "critical", count: 1 }],
        highest_risk_projects: [
          {
            project_name: "Codex Real Trivy",
            open_count: 1,
            overdue_count: 0,
          },
        ],
      },
    })
  })

  await page.route("**/api/projects", async (route) => {
    await route.fulfill({
      json: {
        projects: [
          {
            id: "project-1",
            slug: "codex-real-trivy",
            name: "Codex Real Trivy",
            description: null,
            sla_tracking_enabled: true,
            sla_reporting_enabled: true,
            require_peer_review_for_status_changes: false,
            grace_period_enabled: false,
            grace_period_percent: 100,
          },
        ],
      },
    })
  })

  await page.route("**/api/findings**", async (route) => {
    await route.fulfill({ json: { rows: [] } })
  })

  await page.route("**/api/projects/project-1/assets", async (route) => {
    await route.fulfill({
      json: {
        project_id: "project-1",
        assets: [
          {
            id: "asset-folder-1",
            parent_id: null,
            path: "ubuntu",
            type: "folder",
            name: "ubuntu",
            target_ref: null,
            scan_label: null,
            sla_tracking_enabled: null,
            sla_reporting_enabled: null,
            sort_order: 0,
          },
          {
            id: "asset-folder-2",
            parent_id: "asset-folder-1",
            path: "ubuntu/25.10",
            type: "folder",
            name: "25.10",
            target_ref: null,
            scan_label: null,
            sla_tracking_enabled: null,
            sla_reporting_enabled: null,
            sort_order: 0,
          },
          {
            id: "asset-image-1",
            parent_id: "asset-folder-2",
            path: "ubuntu/25.10/ubuntu:25.10",
            type: "scan_target",
            name: "ubuntu:25.10",
            target_ref: "ubuntu:25.10",
            scan_label: "Trivy Image Scan",
            sla_tracking_enabled: null,
            sla_reporting_enabled: null,
            sort_order: 0,
          },
        ],
      },
    })
  })
}
