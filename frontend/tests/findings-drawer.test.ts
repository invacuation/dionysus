import { describe, expect, test } from "bun:test"

import {
  buildActivity,
  buildCommentsActivity,
  decisionSummaryForActivity,
  descriptionForFindingDetail,
  effectiveStatusPeerReviewRequired,
  nextFindingTableSort,
  reduceFindingDrawerState,
  statusPeerReviewControlState,
  statusSubmitLabel,
  sortDirectionForNewFindingColumn,
} from "../src/features/findings/findings-page"
import type { FindingDetail, Project } from "../src/lib/api"

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

  test("keeps reviewer and decision comment on completed status requests", () => {
    const activity = buildActivity(
      [],
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
          state: "rejected",
          comment: "Ready to close",
          decision_comment: "Patch evidence is incomplete.",
          created_at: "2026-05-08T12:00:00Z",
          decided_at: "2026-05-08T12:10:00Z",
        },
      ],
    )

    expect(activity[0]?.badge).toBe("Request Rejected")
    expect(decisionSummaryForActivity(activity[0])).toBe(
      "Decision by Carol: Patch evidence is incomplete.",
    )
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

  test("includes pending status requests so reviewers can act from activity", () => {
    const activity = buildCommentsActivity(
      [],
      [
        {
          id: "request-1",
          requester_principal_type: "user",
          requester_principal_id: "user-2",
          requester_display: "Bob",
          reviewer_principal_type: null,
          reviewer_principal_id: null,
          reviewer_display: null,
          from_status: "open",
          to_status: "fixed",
          state: "pending",
          comment: "Ready to close",
          decision_comment: null,
          created_at: "2026-05-08T12:00:00Z",
          decided_at: null,
        },
      ],
    )

    expect(activity.map((item) => item.badge)).toEqual(["Request Pending"])
    expect(activity[0]?.request?.id).toBe("request-1")
  })
})

describe("status peer review controls", () => {
  test("locks peer review on when detail policy requires it", () => {
    const detail = {
      project_id: "project-1",
      peer_review_required_for_status_changes: true,
    } as FindingDetail

    expect(effectiveStatusPeerReviewRequired(detail, [], false)).toBe(true)
    expect(statusPeerReviewControlState(detail, [], false)).toEqual({
      checked: true,
      disabled: true,
      label: "Peer review required",
    })
    expect(statusSubmitLabel(false, true)).toBe("Request")
  })

  test("keeps peer review optional when policy does not require it", () => {
    const detail = {
      project_id: "project-1",
      peer_review_required_for_status_changes: false,
    } as FindingDetail

    expect(effectiveStatusPeerReviewRequired(detail, [], false)).toBe(false)
    expect(statusPeerReviewControlState(detail, [], true)).toEqual({
      checked: true,
      disabled: false,
      label: "Require peer review",
    })
    expect(statusSubmitLabel(false, false)).toBe("Change")
  })

  test("uses current project policy when detail policy was cached before the project changed", () => {
    const detail = {
      project_id: "project-1",
      peer_review_required_for_status_changes: false,
    } as FindingDetail

    expect(
      statusPeerReviewControlState(
        detail,
        [
          {
            id: "project-1",
            require_peer_review_for_status_changes: true,
          } as Project,
        ],
        false,
      ),
    ).toEqual({
      checked: true,
      disabled: true,
      label: "Peer review required",
    })
  })
})
