import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { appVersionLabel } from "../src/components/app-shell"

describe("appVersionLabel", () => {
  test("formats the application version for the sidebar", () => {
    expect(appVersionLabel("0.1.0")).toBe("v0.1.0")
  })
})

describe("app shell user summary", () => {
  test("does not show the interactive user's principal type in the sidebar", () => {
    const source = readFileSync(join(import.meta.dir, "../src/components/app-shell.tsx"), "utf8")

    expect(source).not.toContain("{actor.principal_type}")
  })

  test("uses a wide enough desktop sidebar for the system theme label", () => {
    const source = readFileSync(join(import.meta.dir, "../src/components/app-shell.tsx"), "utf8")

    expect(source).toContain("lg:grid-cols-[17rem_1fr]")
  })
})
