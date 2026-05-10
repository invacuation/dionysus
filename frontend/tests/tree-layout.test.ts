import { describe, expect, test } from "bun:test"

import { treeIndentPadding } from "../src/lib/tree-layout"

describe("treeIndentPadding", () => {
  test("keeps increasing after the full indentation step compacts", () => {
    expect(treeIndentPadding(0)).toBe("0.75rem")
    expect(treeIndentPadding(8)).toBe("10.75rem")
    expect(treeIndentPadding(9)).toBe("11.1rem")
    expect(treeIndentPadding(16)).toBe("13.55rem")
  })

  test("normalizes negative depth to the root indent", () => {
    expect(treeIndentPadding(-1)).toBe("0.75rem")
  })
})
