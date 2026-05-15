import { describe, expect, test } from "bun:test"

import {
  buildReleaseOccurrenceSummary,
  buildActivity,
  buildCommentsActivity,
  descriptionForFindingDetail,
  nextFindingTableSort,
  reduceFindingDrawerState,
  sortDirectionForNewFindingColumn,
} from "../src/features/findings/findings-page"
import type { FindingDetail } from "../src/lib/api"

describe("reduceFindingDrawerState", () => {
  test("opens a selected finding in an expanded drawer", () => {
    expect(reduceFindingDrawerState({ selectedFindingId: null, isMinimized: true }, "finding-1")).toEqual({
      selectedFindingId: "finding-1",
      isMinimized: false,
    })
  })

  test("minimizes, restores, and closes without losing the selected finding until close", () => {
    const openState = { selectedFindingId: "finding-1", isMinimized: false }

    expect(reduceFindingDrawerState(openState, "minimize")).toEqual({
      selectedFindingId: "finding-1",
      isMinimized: true,
    })
    expect(reduceFindingDrawerState({ ...openState, isMinimized: true }, "restore")).toEqual(openState)
    expect(reduceFindingDrawerState(openState, "close")).toEqual({
      selectedFindingId: null,
      isMinimized: false,
    })
  })
})

describe("nextFindingTableSort", () => {
  test("selects a new sortable table column with its default direction", () => {
    expect(nextFindingTableSort("last_seen", "desc", "severity")).toEqual({
      sort: "severity",
      direction: "desc",
    })
    expect(nextFindingTableSort("last_seen", "desc", "package")).toEqual({
      sort: "package",
      direction: "asc",
    })
  })

  test("toggles direction when the active table column is selected again", () => {
    expect(nextFindingTableSort("package", "asc", "package")).toEqual({
      sort: "package",
      direction: "desc",
    })
    expect(nextFindingTableSort("package", "desc", "package")).toEqual({
      sort: "package",
      direction: "asc",
    })
  })
})

describe("sortDirectionForNewFindingColumn", () => {
  test("uses useful first-click directions for severity and due-date style columns", () => {
    expect(sortDirectionForNewFindingColumn("severity")).toBe("desc")
    expect(sortDirectionForNewFindingColumn("sla_remaining")).toBe("asc")
    expect(sortDirectionForNewFindingColumn("grace_remaining")).toBe("asc")
  })
})

describe("descriptionForFindingDetail", () => {
  test("falls back to hydrated source evidence when the detail description is blank", () => {
    expect(
      descriptionForFindingDetail({
        description: null,
        source_evidence: {
          title: "Ubuntu package vulnerability",
          description: "Hydrated vulnerability description.",
        },
      } as FindingDetail),
    ).toBe("Hydrated vulnerability description.")
  })
})

describe("buildReleaseOccurrenceSummary", () => {
  test("derives release context labels and values for release-scoped details", () => {
    expect(
      buildReleaseOccurrenceSummary({
        release_context: {
          scope_asset_id: "scope-1",
          scope_path: "releases/V40",
          version_asset_id: "version-1",
          version: "40.0.3",
        },
        related_occurrences: [],
      } as FindingDetail)?.terms,
    ).toEqual([
      { label: "Release line", value: "releases/V40" },
      { label: "Release version", value: "40.0.3" },
    ])
  })

  test("formats related occurrence rows with compact finding state", () => {
    expect(
      buildReleaseOccurrenceSummary({
        release_context: {
          scope_asset_id: "scope-1",
          scope_path: "releases/V40",
          version_asset_id: "version-3",
          version: "40.0.3",
        },
        related_occurrences: [
          {
            finding_id: "finding-1",
            release_version: "40.0.1",
            project_name: "Alpha",
            scan_target_name: "api-image-40.0.1",
            scan_target_path: "releases/V40/40.0.1/images/api",
            status: "accepted_risk",
            present_in_latest_scan: false,
            installed_version: "3.0.11-1",
            fixed_version: "3.0.13-1",
          },
        ],
      } as FindingDetail)?.occurrences,
    ).toEqual([
      {
        id: "finding-1",
        releaseVersion: "40.0.1",
        scanTargetPath: "releases/V40/40.0.1/images/api",
        status: "Accepted Risk",
        latestPresence: "Absent from latest scan",
        installedVersion: "3.0.11-1",
        fixedVersion: "3.0.13-1",
      },
    ])
  })

  test("returns no release occurrence view model for non-release details", () => {
    expect(
      buildReleaseOccurrenceSummary({
        release_context: null,
        related_occurrences: [],
      } as FindingDetail),
    ).toBeNull()
  })
})

describe("buildActivity", () => {
  test("includes import and hydration audit entries in the changelog", () => {
    const activity = buildActivity(
      [
        {
          id: "comment-1",
          body: "Investigating with platform team.",
          author_principal_type: "user",
          author_principal_id: "user-1",
          author_display: "Alice",
          created_at: "2026-05-08T12:30:00Z",
          is_system: false,
          status_from: null,
          status_to: null,
        },
      ],
      [],
      {
        first_detected_at: "2026-05-08T12:00:00Z",
        last_seen_at: "2026-05-08T12:05:00Z",
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001"],
        source_evidence: { enrichment: { cve_source_links: ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001"] } },
      } as FindingDetail,
    )

    expect(activity.map((item) => item.badge)).toEqual(["Import", "Hydration"])
  })
})

describe("buildCommentsActivity", () => {
  test("keeps comments separate from lifecycle changelog entries", () => {
    const activity = buildCommentsActivity(
      [
        {
          id: "comment-1",
          body: "Investigating with platform team.",
          author_principal_type: "user",
          author_principal_id: "user-1",
          author_display: "Alice",
          created_at: "2026-05-08T12:30:00Z",
          is_system: false,
          status_from: null,
          status_to: null,
        },
      ],
      [
        {
          id: "request-1",
          requester_principal_type: "user",
          requester_principal_id: "user-2",
          requester_display: "Bob",
          reviewer_principal_type: "user",
          reviewer_principal_id: "user-3",
          reviewer_display: "Carol",
          from_status: "open",
          to_status: "fixed",
          state: "approved",
          comment: "Ready to close",
          decision_comment: "Approved",
          created_at: "2026-05-08T12:00:00Z",
          decided_at: "2026-05-08T12:10:00Z",
        },
      ],
    )

    expect(activity.map((item) => item.badge)).toEqual(["Comment"])
  })
})
