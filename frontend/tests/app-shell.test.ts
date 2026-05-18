import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import {
  appVersionLabel,
  homeRouteForActor,
  visibleNavItemsForActor,
} from "../src/components/app-shell"
import type { ActorMetadata } from "../src/lib/api"

function actorWithCapabilities(
  navigation: ActorMetadata["capabilities"]["navigation"],
): ActorMetadata {
  return {
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
    capabilities: {
      navigation,
      admin: {
        access: false,
        audit_log: false,
        import_history: false,
        machine_credentials: false,
        permission_tester: false,
        sessions: false,
        security_settings: false,
      },
    },
  }
}

describe("appVersionLabel", () => {
  test("formats the application version for the sidebar", () => {
    expect(appVersionLabel("0.1.0")).toBe("v0.1.0")
  })
})

describe("visibleNavItemsForActor", () => {
  test("omits sidebar tabs the current actor cannot access", () => {
    const actor = actorWithCapabilities({
      overview: false,
      findings: true,
      inventory: true,
      imports: false,
      admin: false,
    })

    expect(visibleNavItemsForActor(actor).map((item) => item.route)).toEqual([
      "findings",
      "inventory",
    ])
  })
})

describe("homeRouteForActor", () => {
  test("prefers findings when the current actor can access it", () => {
    const actor = actorWithCapabilities({
      overview: true,
      findings: true,
      inventory: true,
      imports: false,
      admin: false,
    })

    expect(homeRouteForActor(actor)).toBe("findings")
  })

  test("falls back to the first accessible route when findings is not available", () => {
    const actor = actorWithCapabilities({
      overview: true,
      findings: false,
      inventory: true,
      imports: false,
      admin: false,
    })

    expect(homeRouteForActor(actor)).toBe("overview")
  })

  test("returns no home route when the current actor cannot access any areas", () => {
    const actor = actorWithCapabilities({
      overview: false,
      findings: false,
      inventory: false,
      imports: false,
      admin: false,
    })

    expect(homeRouteForActor(actor)).toBeNull()
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
