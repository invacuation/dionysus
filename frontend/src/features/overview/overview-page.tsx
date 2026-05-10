import { AlertCircle } from "lucide-react"
import { useQuery } from "@tanstack/react-query"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { getJson, type EstateOverview, type SeverityCount } from "@/lib/api"
import { formatSeverityLabel, severityGradientClassName, severityRank } from "@/lib/severity"

function metricLabel(value: number) {
  return new Intl.NumberFormat().format(value)
}

type OverviewSeverityRow = SeverityCount & {
  label: string
  className: string
}

export function findingSeverityHref(severity: string): string {
  return `/findings?severity=${encodeURIComponent(severity.trim().toLocaleLowerCase())}`
}

export function findingProjectHref(projectId: string): string {
  return `/findings?project_id=${encodeURIComponent(projectId)}`
}

export function overviewSeverityRows(rows: SeverityCount[]): OverviewSeverityRow[] {
  return rows
    .map((row) => {
      return {
        ...row,
        label: formatSeverityLabel(row.severity),
        className: severityGradientClassName(row.severity),
      }
    })
    .sort((a, b) => {
      const aRank = severityRank(a.severity)
      const bRank = severityRank(b.severity)

      if (aRank !== bRank) {
        return aRank - bRank
      }

      return a.label.localeCompare(b.label)
    })
}

export function OverviewPage() {
  const query = useQuery({
    queryKey: ["overview"],
    queryFn: () => getJson<EstateOverview>("/api/overview"),
  })

  if (query.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading estate overview...</p>
  }

  if (query.isError || !query.data) {
    return (
      <Card className="max-w-xl">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertCircle className="size-4 text-destructive" aria-hidden="true" />
            <CardTitle className="text-base">Unable to load overview</CardTitle>
          </div>
          <CardDescription>The backend API did not return overview data.</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const overview = query.data
  const severityRows = overviewSeverityRows(overview.severity_counts)

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-normal">Overview</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Current vulnerability posture across imported projects and assets.
          </p>
        </div>
      </header>

      <section className="grid gap-3 md:grid-cols-3">
        <MetricCard label="Open Findings" value={overview.open_findings} />
        <MetricCard label="Overdue SLAs" value={overview.overdue_sla} />
        <MetricCard label="Grace-period risk" value={overview.grace_period_risk} />
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Open Severities</CardTitle>
            <CardDescription>Open findings grouped by scanner severity.</CardDescription>
          </CardHeader>
          <CardContent>
            {severityRows.length === 0 ? (
              <p className="text-sm text-muted-foreground">No open findings yet.</p>
            ) : (
              <ul className="space-y-2">
                {severityRows.map((row) => (
                  <li
                    className={`flex items-center justify-between rounded-md border px-3 py-2 text-sm ${row.className}`}
                    key={row.severity}
                  >
                    <span className="font-medium">{row.label}</span>
                    <a
                      className="rounded-sm font-semibold underline-offset-4 outline-none hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50"
                      href={findingSeverityHref(row.severity)}
                    >
                      {metricLabel(row.count)}
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Highest-Risk Projects</CardTitle>
            <CardDescription>Projects ranked by open and overdue findings.</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.highest_risk_projects.length === 0 ? (
              <p className="text-sm text-muted-foreground">No project risk to show.</p>
            ) : (
              <div className="space-y-2">
                {overview.highest_risk_projects.map((project) => (
                  <a
                    className="grid gap-2 rounded-md border px-3 py-2 text-sm sm:grid-cols-[1fr_auto_auto] sm:items-center sm:gap-3"
                    href={findingProjectHref(project.project_id)}
                    key={project.project_id}
                  >
                    <span className="font-medium">{project.project_name}</span>
                    <span className="text-muted-foreground">
                      {metricLabel(project.open_count)} open
                    </span>
                    <span className="text-muted-foreground">
                      {metricLabel(project.overdue_count)} overdue
                    </span>
                  </a>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  )
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <strong className="text-3xl font-semibold tracking-normal">
          {metricLabel(value)}
        </strong>
      </CardContent>
    </Card>
  )
}
