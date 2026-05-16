import { expect, test } from "@playwright/test"

const realBackendEnabled = process.env.E2E_REAL_BACKEND === "1"

test.skip(!realBackendEnabled, "deployed backend e2e runs only against a real app server")

test("signs in to the deployed Go-backed app and loads core workspaces", async ({ page }) => {
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
})
