import { describe, expect, test } from "bun:test"

import {
  nextFindingTableSort,
  reduceFindingDrawerState,
  sortDirectionForNewFindingColumn,
} from "../src/features/findings/findings-page"

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
