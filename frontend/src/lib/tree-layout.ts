const baseIndentRem = 0.75
const fullStepRem = 1.25
const compactStepRem = 0.35
const compactAfterDepth = 8

export function treeIndentPadding(depth: number): string {
  const safeDepth = Math.max(0, depth)
  const fullDepth = Math.min(safeDepth, compactAfterDepth)
  const compactDepth = Math.max(0, safeDepth - compactAfterDepth)
  const indent = baseIndentRem + fullDepth * fullStepRem + compactDepth * compactStepRem
  return `${indent}rem`
}
