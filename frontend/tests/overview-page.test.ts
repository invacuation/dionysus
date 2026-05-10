import { describe, expect, test } from "bun:test"

import {
  findingProjectHref,
  findingSeverityHref,
  overviewSeverityRows,
} from "../src/features/overview/overview-page"
import { severityPillClassName } from "../src/lib/severity"
import type { SeverityCount } from "../src/lib/api"

describe("overviewSeverityRows", () => {
  test("orders known severities by rank and unexpected severities by label", () => {
    const rows: SeverityCount[] = [
      { severity: "LOW", count: 8 },
      { severity: "HIGH", count: 2 },
      { severity: "negligible", count: 1 },
      { severity: "CRITICAL", count: 1 },
      { severity: "MEDIUM", count: 5 },
      { severity: "informational", count: 3 },
      { severity: "UNKNOWN", count: 4 },
    ]

    expect(overviewSeverityRows(rows).map((row) => row.label)).toEqual([
      "Critical",
      "High",
      "Medium",
      "Low",
      "Informational",
      "Unknown",
      "Negligible",
    ])
  })

  test("normalizes known labels and assigns severity-specific color treatment", () => {
    const rows: SeverityCount[] = [
      { severity: "critical", count: 1 },
      { severity: "HIGH", count: 2 },
      { severity: "medium", count: 3 },
      { severity: "Low", count: 4 },
      { severity: "Informational", count: 6 },
      { severity: "unknown", count: 5 },
    ]

    expect(
      overviewSeverityRows(rows).map((row) => ({
        label: row.label,
        className: row.className,
      })),
    ).toEqual([
      { label: "Critical", className: expect.stringContaining("to-red-100") },
      { label: "High", className: expect.stringContaining("to-orange-100") },
      { label: "Medium", className: expect.stringContaining("to-amber-100") },
      { label: "Low", className: expect.stringContaining("to-green-100") },
      { label: "Informational", className: expect.stringContaining("to-cyan-100") },
      { label: "Unknown", className: expect.stringContaining("to-slate-100") },
    ])
  })

  test("uses solid color treatment for compact severity pills", () => {
    expect(severityPillClassName("medium")).toContain("bg-amber-400")
    expect(severityPillClassName("medium")).not.toContain("bg-gradient")
  })
})

describe("overview finding links", () => {
  test("builds scoped findings links from severity and project rows", () => {
    expect(findingSeverityHref("Critical")).toBe("/findings?severity=critical")
    expect(findingProjectHref("project-1")).toBe("/findings?project_id=project-1")
  })
})
