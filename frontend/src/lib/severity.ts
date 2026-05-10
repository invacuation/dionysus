export const severityOrder = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
  "UNKNOWN",
] as const

const severityRanks = new Map<string, number>(
  severityOrder.map((severity, index) => [severity, index]),
)

const severityGradientClassNames: Record<string, string> = {
  CRITICAL:
    "border-red-300 bg-gradient-to-r from-transparent to-red-100 text-red-950 dark:border-red-800/75 dark:to-red-950/50 dark:text-red-100",
  HIGH:
    "border-orange-300 bg-gradient-to-r from-transparent to-orange-100 text-orange-950 dark:border-orange-800/75 dark:to-orange-950/50 dark:text-orange-100",
  MEDIUM:
    "border-amber-300 bg-gradient-to-r from-transparent to-amber-100 text-amber-950 dark:border-amber-800/75 dark:to-amber-950/50 dark:text-amber-100",
  LOW:
    "border-green-300 bg-gradient-to-r from-transparent to-green-100 text-green-950 dark:border-green-800/75 dark:to-green-950/50 dark:text-green-100",
  INFORMATIONAL:
    "border-cyan-300 bg-gradient-to-r from-transparent to-cyan-100 text-cyan-950 dark:border-cyan-800/75 dark:to-cyan-950/50 dark:text-cyan-100",
  UNKNOWN:
    "border-slate-300 bg-gradient-to-r from-transparent to-slate-100 text-slate-950 dark:border-slate-700/80 dark:to-slate-800/70 dark:text-slate-100",
}

const fallbackSeverityGradientClassName =
  "border-slate-300 bg-gradient-to-r from-transparent to-slate-100 text-slate-950 dark:border-slate-700/80 dark:to-slate-800/70 dark:text-slate-100"

const severityPillClassNames: Record<string, string> = {
  CRITICAL:
    "border-red-700 bg-red-700 text-white dark:border-red-500 dark:bg-red-500 dark:text-red-950",
  HIGH:
    "border-orange-600 bg-orange-600 text-white dark:border-orange-400 dark:bg-orange-400 dark:text-orange-950",
  MEDIUM:
    "border-amber-500 bg-amber-400 text-amber-950 dark:border-amber-300 dark:bg-amber-300 dark:text-amber-950",
  LOW:
    "border-green-600 bg-green-600 text-white dark:border-green-400 dark:bg-green-400 dark:text-green-950",
  INFORMATIONAL:
    "border-cyan-600 bg-cyan-600 text-white dark:border-cyan-400 dark:bg-cyan-400 dark:text-cyan-950",
  UNKNOWN:
    "border-slate-600 bg-slate-600 text-white dark:border-slate-400 dark:bg-slate-400 dark:text-slate-950",
}

const fallbackSeverityPillClassName =
  "border-slate-600 bg-slate-600 text-white dark:border-slate-400 dark:bg-slate-400 dark:text-slate-950"

export function formatSeverityLabel(severity: string): string {
  return severity
    .trim()
    .toLowerCase()
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ")
}

export function severityGradientClassName(severity: string): string {
  const normalized = severity.trim().toUpperCase()
  return severityGradientClassNames[normalized] ?? fallbackSeverityGradientClassName
}

export function severityPillClassName(severity: string): string {
  const normalized = severity.trim().toUpperCase()
  return severityPillClassNames[normalized] ?? fallbackSeverityPillClassName
}

export function severityRank(severity: string): number {
  return severityRanks.get(severity.trim().toUpperCase()) ?? Number.POSITIVE_INFINITY
}
