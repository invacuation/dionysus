import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Box,
  ExternalLink,
  Folder,
  FolderTree,
  PanelRightClose,
  PanelRightOpen,
  PackageSearch,
  Search,
  ShieldAlert,
  X,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  approveFindingStatusRequest,
  createFindingComment,
  getFinding,
  listProjectAssets,
  listFindings,
  listProjects,
  rejectFindingStatusRequest,
  retractFindingStatusRequest,
  updateFindingStatus,
  type ActorMetadata,
  type Asset,
  type FindingComment,
  type FindingDetail,
  type FindingListParams,
  type FindingRow,
  type FindingSortKey,
  type FindingStatus,
  type FindingStatusChangeRequest,
  type Project,
  type SortDirection,
} from "@/lib/api"
import { severityPillClassName } from "@/lib/severity"
import { cn } from "@/lib/utils"

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]
const folderType = "folder"
const scanTargetType = "scan_target"

const statuses: Array<{ value: FindingStatus; label: string }> = [
  { value: "open", label: "Open" },
  { value: "accepted_risk", label: "Accepted Risk" },
  { value: "false_positive", label: "False Positive" },
  { value: "mitigated", label: "Mitigated" },
  { value: "suppressed", label: "Suppressed" },
  { value: "fixed", label: "Fixed" },
]

const sortOptions: Array<{ value: FindingSortKey; label: string }> = [
  { value: "last_seen", label: "Last seen" },
  { value: "severity", label: "Severity" },
  { value: "first_detected", label: "First detected" },
  { value: "package", label: "Package" },
  { value: "installed_version", label: "Installed" },
  { value: "fixed_version", label: "Fixed" },
  { value: "identifier", label: "Identifier" },
  { value: "project", label: "Project / asset" },
  { value: "status", label: "Status" },
  { value: "sla_remaining", label: "SLA remaining" },
  { value: "grace_remaining", label: "Grace remaining" },
]

type Filters = {
  severity: string
  status: "" | FindingStatus
  identifier: string
  packageName: string
  presentInLatestScan: "all" | "true" | "false"
  fixAvailable: "all" | "true" | "false"
  sort: FindingSortKey
  direction: SortDirection
}

export type FindingInventoryScope = {
  projectId: string
  assetId: string
}

type FindingDrawerState = {
  selectedFindingId: string | null
  isMinimized: boolean
}

type FindingDrawerAction = string | "close" | "minimize" | "restore"

type FindingTableSort = Pick<Filters, "direction" | "sort">

export type FindingInventoryTreeRow =
  | {
      kind: "up"
      id: string
      label: string
    }
  | {
      kind: "asset"
      asset: Asset
    }

export function reduceFindingDrawerState(
  state: FindingDrawerState,
  action: FindingDrawerAction,
): FindingDrawerState {
  if (action === "close") {
    return { selectedFindingId: null, isMinimized: false }
  }
  if (action === "minimize") {
    return state.selectedFindingId ? { ...state, isMinimized: true } : state
  }
  if (action === "restore") {
    return state.selectedFindingId ? { ...state, isMinimized: false } : state
  }
  return { selectedFindingId: action, isMinimized: false }
}

export const defaultFindingFilters: Filters = {
  severity: "",
  status: "",
  identifier: "",
  packageName: "",
  presentInLatestScan: "all",
  fixAvailable: "all",
  sort: "last_seen",
  direction: "desc",
}

const defaultInventoryScope: FindingInventoryScope = {
  projectId: "",
  assetId: "",
}

export function FindingsPage({ currentActor }: { currentActor: ActorMetadata }) {
  const [filters, setFilters] = useState<Filters>(() =>
    findingFiltersFromSearchParams(new URLSearchParams(window.location.search)),
  )
  const [inventoryScope, setInventoryScope] =
    useState<FindingInventoryScope>(() =>
      findingInventoryScopeFromSearchParams(new URLSearchParams(window.location.search)),
    )
  const [projectSearch, setProjectSearch] = useState("")
  const [assetSearch, setAssetSearch] = useState("")
  const [currentFolderId, setCurrentFolderId] = useState("")
  const [drawerState, setDrawerState] = useState<FindingDrawerState>({
    selectedFindingId: null,
    isMinimized: false,
  })
  const params = useMemo(() => findingParams(filters, inventoryScope), [filters, inventoryScope])
  const selectedFindingId = drawerState.selectedFindingId

  const projectsQuery = useQuery({
    queryKey: ["projects"],
    queryFn: listProjects,
  })
  const projects = projectsQuery.data?.projects ?? []
  const visibleProjects = useMemo(
    () => filterScopeProjects(projects, projectSearch),
    [projects, projectSearch],
  )
  const assetsQuery = useQuery({
    queryKey: ["projects", inventoryScope.projectId, "assets"],
    queryFn: () => listProjectAssets(inventoryScope.projectId),
    enabled: inventoryScope.projectId.length > 0,
  })
  const assets = assetsQuery.data?.assets ?? []
  const visibleAssets = useMemo(() => filterScopeAssets(assets, assetSearch), [assets, assetSearch])
  const assetTreeRows = useMemo(
    () => findingInventoryBrowserRows(assets, assetSearch, currentFolderId),
    [assets, assetSearch, currentFolderId],
  )
  const scopeLabel = inventoryScopeLabel(inventoryScope, projects, assets)

  const findingsQuery = useQuery({
    queryKey: ["findings", params],
    queryFn: () => listFindings(params),
  })

  const rows = findingsQuery.data?.rows ?? []
  const detailQuery = useQuery({
    queryKey: ["findings", selectedFindingId],
    queryFn: () => getFinding(selectedFindingId ?? ""),
    enabled: selectedFindingId !== null,
  })

  useEffect(() => {
    setCurrentFolderId("")
  }, [inventoryScope.projectId])

  useEffect(() => {
    if (currentFolderId && !assets.some((asset) => asset.id === currentFolderId)) {
      setCurrentFolderId("")
    }
  }, [assets, currentFolderId])

  useEffect(() => {
    if (
      selectedFindingId &&
      findingsQuery.isSuccess &&
      !rows.some((row) => row.id === selectedFindingId)
    ) {
      setDrawerState((current) => reduceFindingDrawerState(current, "close"))
    }
  }, [findingsQuery.isSuccess, rows, selectedFindingId])

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-2">
          <div>
            <h1 className="text-2xl font-semibold tracking-normal">Findings</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              Filter, sort, inspect, and resolve scanner findings across projects.
            </p>
          </div>
        </div>
        <Button
          disabled={isDefaultFilters(filters)}
          onClick={() => {
            setFilters(defaultFindingFilters)
            setDrawerState((current) => reduceFindingDrawerState(current, "close"))
          }}
          size="sm"
          type="button"
          variant="outline"
        >
          Clear filters
        </Button>
      </header>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <CardTitle className="text-base">Inventory</CardTitle>
            </div>
            <Button
              disabled={isDefaultInventoryScope(inventoryScope)}
              onClick={() => {
                setInventoryScope(defaultInventoryScope)
                setProjectSearch("")
                setAssetSearch("")
                setDrawerState((current) => reduceFindingDrawerState(current, "close"))
              }}
              size="sm"
              type="button"
              variant="outline"
            >
              Reset scope
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
            <InventoryProjectList
              isError={projectsQuery.isError}
              isLoading={projectsQuery.isPending}
              onSearchChange={setProjectSearch}
              onSelectProject={(projectId) => {
                setInventoryScope({ assetId: "", projectId })
                setAssetSearch("")
                setCurrentFolderId("")
                setDrawerState((current) => reduceFindingDrawerState(current, "close"))
              }}
              projects={visibleProjects}
              search={projectSearch}
              selectedProjectId={inventoryScope.projectId}
            />
            <div className="space-y-2">
              <Field label="Folders / assets">
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
                    aria-hidden="true"
                  />
                  <Input
                    className="pl-9"
                    disabled={!inventoryScope.projectId}
                    onChange={(event) => setAssetSearch(event.target.value)}
                    placeholder="Search folders and assets"
                    value={assetSearch}
                  />
                </div>
              </Field>
              <InventoryScopeTree
                assetRows={assetTreeRows}
                assets={assets}
                isError={assetsQuery.isError}
                isLoading={assetsQuery.isPending && inventoryScope.projectId.length > 0}
                onSelectAsset={(assetId) => {
                  setInventoryScope((current) => ({ ...current, assetId }))
                  const asset = assets.find((candidate) => candidate.id === assetId)
                  if (asset?.type === folderType) {
                    setCurrentFolderId(asset.id)
                  }
                  setDrawerState((current) => reduceFindingDrawerState(current, "close"))
                }}
                onSelectRoot={() => {
                  setInventoryScope((current) => ({ ...current, assetId: "" }))
                  setCurrentFolderId("")
                  setDrawerState((current) => reduceFindingDrawerState(current, "close"))
                }}
                onSelectUp={() => {
                  const currentFolder = assets.find((asset) => asset.id === currentFolderId)
                  const parentId = currentFolder?.parent_id ?? ""
                  setCurrentFolderId(parentId)
                  setInventoryScope((current) => ({ ...current, assetId: parentId }))
                  setDrawerState((current) => reduceFindingDrawerState(current, "close"))
                }}
                projectSelected={inventoryScope.projectId.length > 0}
                selectedAssetId={inventoryScope.assetId}
                visibleAssets={visibleAssets}
              />
            </div>
          </div>
          {assetsQuery.isError ? (
            <StateMessage label="Unable to load assets for this project." tone="error" />
          ) : null}
        </CardContent>
      </Card>

      <section className="grid gap-3 rounded-lg border bg-card p-3 lg:grid-cols-[repeat(7,minmax(0,1fr))_auto] lg:items-end">
        <Field label="Severity">
          <Select
            value={filters.severity}
            onChange={(value) => setFilters((current) => ({ ...current, severity: value }))}
          >
            <option value="">All severities</option>
            {severities.map((severity) => (
              <option key={severity} value={severity}>
                {formatSeverity(severity)}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Status">
          <Select
            value={filters.status}
            onChange={(value) =>
              setFilters((current) => ({ ...current, status: value as Filters["status"] }))
            }
          >
            <option value="">All statuses</option>
            {statuses.map((status) => (
              <option key={status.value} value={status.value}>
                {status.label}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Identifier">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              className="pl-9"
              onChange={(event) =>
                setFilters((current) => ({ ...current, identifier: event.target.value }))
              }
              placeholder="CVE or CWE"
              value={filters.identifier}
            />
          </div>
        </Field>

        <Field label="Package">
          <Input
            onChange={(event) =>
              setFilters((current) => ({ ...current, packageName: event.target.value }))
            }
            placeholder="openssl"
            value={filters.packageName}
          />
        </Field>

        <Field label="Latest scan">
          <Select
            value={filters.presentInLatestScan}
            onChange={(value) =>
              setFilters((current) => ({
                ...current,
                presentInLatestScan: value as Filters["presentInLatestScan"],
              }))
            }
          >
            <option value="all">All findings</option>
            <option value="true">Present</option>
            <option value="false">Absent</option>
          </Select>
        </Field>

        <Field label="Fix available">
          <Select
            value={filters.fixAvailable}
            onChange={(value) =>
              setFilters((current) => ({
                ...current,
                fixAvailable: value as Filters["fixAvailable"],
              }))
            }
          >
            <option value="all">All findings</option>
            <option value="true">Fix available</option>
            <option value="false">No fix available</option>
          </Select>
        </Field>

        <Field label="Sort">
          <Select
            value={filters.sort}
            onChange={(value) =>
              setFilters((current) => ({ ...current, sort: value as FindingSortKey }))
            }
          >
            {sortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Direction">
          <Select
            value={filters.direction}
            onChange={(value) =>
              setFilters((current) => ({ ...current, direction: value as SortDirection }))
            }
          >
            <option value="desc">Desc</option>
            <option value="asc">Asc</option>
          </Select>
        </Field>
      </section>

      <section>
        <Card className="overflow-hidden py-0">
          <div className="flex items-center justify-between border-b px-4 py-3">
            <div>
              <h2 className="text-sm font-semibold">Findings</h2>
              <p className="text-xs text-muted-foreground">
                {resultLabel(findingsQuery.isPending, rows.length, scopeLabel)}
              </p>
            </div>
          </div>
          <CardContent className="p-0">
            <FindingsTable
              direction={filters.direction}
              isError={findingsQuery.isError}
              isLoading={findingsQuery.isPending}
              onSelect={(id) => setDrawerState((current) => reduceFindingDrawerState(current, id))}
              onSort={(sort) =>
                setFilters((current) => ({
                  ...current,
                  ...nextFindingTableSort(current.sort, current.direction, sort),
                }))
              }
              rows={rows}
              selectedFindingId={selectedFindingId}
              sort={filters.sort}
            />
          </CardContent>
        </Card>
      </section>

      <FindingDrawer
        currentActor={currentActor}
        detail={detailQuery.data ?? null}
        error={detailQuery.error}
        isError={detailQuery.isError}
        isLoading={detailQuery.isPending && selectedFindingId !== null}
        isMinimized={drawerState.isMinimized}
        onClose={() => setDrawerState((current) => reduceFindingDrawerState(current, "close"))}
        onMinimize={() => setDrawerState((current) => reduceFindingDrawerState(current, "minimize"))}
        onRestore={() => setDrawerState((current) => reduceFindingDrawerState(current, "restore"))}
        projects={projects}
        selectedFindingId={selectedFindingId}
      />
    </div>
  )
}

export function findingParams(
  filters: Filters,
  inventoryScope: FindingInventoryScope = defaultInventoryScope,
): FindingListParams {
  const identifier = filters.identifier.trim()
  const packageName = filters.packageName.trim()
  return {
    project_id: inventoryScope.projectId || undefined,
    asset_id: inventoryScope.assetId || undefined,
    severity: filters.severity || undefined,
    status: filters.status || undefined,
    identifier: identifier || undefined,
    package: packageName || undefined,
    present_in_latest_scan:
      filters.presentInLatestScan === "all" ? undefined : filters.presentInLatestScan === "true",
    fix_available: filters.fixAvailable === "all" ? undefined : filters.fixAvailable === "true",
    sort: filters.sort,
    direction: filters.direction,
  }
}

function isDefaultFilters(filters: Filters): boolean {
  return JSON.stringify(filters) === JSON.stringify(defaultFindingFilters)
}

function isDefaultInventoryScope(scope: FindingInventoryScope): boolean {
  return scope.projectId === "" && scope.assetId === ""
}

export function inventoryScopeLabel(
  scope: FindingInventoryScope,
  projects: Project[],
  assets: Asset[],
): string {
  if (!scope.projectId) {
    return "the entire inventory"
  }
  const project = projects.find((candidate) => candidate.id === scope.projectId)
  const projectName = project?.name ?? "selected project"
  if (!scope.assetId) {
    return projectName
  }
  const asset = assets.find((candidate) => candidate.id === scope.assetId)
  return asset ? `${projectName} / ${assetNameBreadcrumb(asset, assets).join(" / ")}` : projectName
}

function assetNameBreadcrumb(asset: Asset, assets: Asset[]): string[] {
  const assetsById = new Map(assets.map((candidate) => [candidate.id, candidate]))
  const names = [asset.name]
  const visited = new Set([asset.id])
  let parentId = asset.parent_id

  while (parentId) {
    const parent = assetsById.get(parentId)
    if (!parent || visited.has(parent.id)) {
      break
    }
    names.unshift(parent.name)
    visited.add(parent.id)
    parentId = parent.parent_id
  }

  return names
}

export function filterScopeProjects(projects: Project[], query: string): Project[] {
  const normalizedQuery = normalizeSearchQuery(query)
  if (!normalizedQuery) {
    return projects
  }
  return projects.filter((project) =>
    searchMatches(normalizedQuery, [project.name, project.slug, project.description]),
  )
}

function projectLabel(project: Project): string {
  return project.slug && project.slug !== project.name
    ? `${project.name} / ${project.slug}`
    : project.name
}

export function filterScopeAssets(assets: Asset[], query: string): Asset[] {
  const normalizedQuery = normalizeSearchQuery(query)
  if (!normalizedQuery) {
    return assets
  }

  const assetsById = new Map(assets.map((asset) => [asset.id, asset]))
  const includedIds = new Set<string>()

  for (const asset of assets) {
    if (
      !searchMatches(normalizedQuery, [
        asset.name,
        asset.path,
        asset.type,
        asset.target_ref,
        asset.scan_label,
      ])
    ) {
      continue
    }

    includedIds.add(asset.id)
    let parentId = asset.parent_id
    while (parentId) {
      const parent = assetsById.get(parentId)
      if (!parent || includedIds.has(parent.id)) {
        break
      }
      includedIds.add(parent.id)
      parentId = parent.parent_id
    }
  }

  return assets.filter((asset) => includedIds.has(asset.id))
}

export function findingInventoryBrowserRows(
  assets: Asset[],
  query: string,
  currentFolderId: string,
): FindingInventoryTreeRow[] {
  const normalizedQuery = normalizeSearchQuery(query)
  const assetsById = new Map(assets.map((asset) => [asset.id, asset]))
  const currentFolder = currentFolderId ? assetsById.get(currentFolderId) : null
  const parentId = currentFolder?.id ?? null
  const rows: FindingInventoryTreeRow[] = []

  if (currentFolder) {
    rows.push({ kind: "up", id: `up:${currentFolder.id}`, label: "Go up one folder" })
  }

  const directChildren = assets
    .filter((asset) => (asset.parent_id ?? null) === parentId)
    .filter((asset) =>
      normalizedQuery
        ? searchMatches(normalizedQuery, [
            asset.name,
            asset.path,
            asset.type,
            asset.target_ref,
            asset.scan_label,
          ])
        : true,
    )
    .sort(compareScopeAssets)

  rows.push(...directChildren.map((asset) => ({ kind: "asset" as const, asset })))
  return rows
}

function normalizeSearchQuery(query: string): string {
  return query.trim().toLocaleLowerCase()
}

function searchMatches(query: string, fields: Array<string | null | undefined>): boolean {
  return fields.some((field) => field?.toLocaleLowerCase().includes(query))
}

function compareScopeAssets(left: Asset, right: Asset): number {
  return left.sort_order - right.sort_order || left.name.localeCompare(right.name)
}

function InventoryProjectList({
  isError,
  isLoading,
  onSearchChange,
  onSelectProject,
  projects,
  search,
  selectedProjectId,
}: {
  isError: boolean
  isLoading: boolean
  onSearchChange: (value: string) => void
  onSelectProject: (projectId: string) => void
  projects: Project[]
  search: string
  selectedProjectId: string
}) {
  return (
    <div className="space-y-2">
      <Field label="Projects">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            className="pl-9"
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search projects"
            value={search}
          />
        </div>
      </Field>

      <div className="max-h-80 overflow-y-auto rounded-md border">
        <button
          aria-current={!selectedProjectId ? "true" : undefined}
          className={cn(
            "grid min-h-12 w-full gap-1 border-b border-dashed px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
            !selectedProjectId && "bg-accent text-accent-foreground",
          )}
          onClick={() => onSelectProject("")}
          type="button"
        >
          <span className="truncate font-medium">Entire inventory</span>
          <span className="truncate text-xs text-muted-foreground">All projects</span>
        </button>

        {isLoading ? (
          <div className="p-3">
            <StateMessage label="Loading projects..." />
          </div>
        ) : isError ? (
          <div className="p-3">
            <StateMessage label="Unable to load projects." tone="error" />
          </div>
        ) : projects.length === 0 ? (
          <div className="p-3">
            <StateMessage label="No projects match this search." />
          </div>
        ) : (
          <ul className="divide-y">
            {projects.map((project) => (
              <li key={project.id}>
                <button
                  aria-current={selectedProjectId === project.id ? "true" : undefined}
                  className={cn(
                    "grid min-h-12 w-full gap-1 px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
                    selectedProjectId === project.id && "bg-accent text-accent-foreground",
                  )}
                  onClick={() => onSelectProject(project.id)}
                  type="button"
                >
                  <span className="truncate font-medium">{project.name}</span>
                  <span className="truncate text-xs text-muted-foreground">{project.slug}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function InventoryScopeTree({
  assetRows,
  assets,
  isError,
  isLoading,
  onSelectAsset,
  onSelectRoot,
  onSelectUp,
  projectSelected,
  selectedAssetId,
  visibleAssets,
}: {
  assetRows: FindingInventoryTreeRow[]
  assets: Asset[]
  isError: boolean
  isLoading: boolean
  onSelectAsset: (assetId: string) => void
  onSelectRoot: () => void
  onSelectUp: () => void
  projectSelected: boolean
  selectedAssetId: string
  visibleAssets: Asset[]
}) {
  if (!projectSelected) {
    return <StateMessage label="Select a project to browse its inventory." />
  }

  if (isLoading) {
    return <StateMessage label="Loading project inventory..." />
  }

  if (isError) {
    return <StateMessage label="Unable to load project inventory." tone="error" />
  }

  if (assets.length === 0) {
    return <StateMessage label="This project does not have inventory assets yet." />
  }

  if (visibleAssets.length === 0 || assetRows.length === 0) {
    return <StateMessage label="No inventory entries match this search." />
  }

  return (
    <div className="max-h-80 overflow-y-auto rounded-md border">
      <button
        aria-current={!selectedAssetId ? "true" : undefined}
        className={cn(
          "flex min-h-10 w-full items-center gap-2 border-b border-dashed px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
          !selectedAssetId && "bg-accent text-accent-foreground",
        )}
        onClick={onSelectRoot}
        type="button"
      >
        <FolderTree className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="truncate font-medium">Root</span>
      </button>
      <ul className="divide-y">
        {assetRows.map((row) =>
          row.kind === "up" ? (
            <li key={row.id}>
              <button
                className="flex min-h-10 w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-accent"
                onClick={onSelectUp}
                type="button"
              >
                <ArrowUp className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="truncate font-medium">{row.label}</span>
              </button>
            </li>
          ) : (
            <FindingInventoryTreeNode
              asset={row.asset}
              isSelected={selectedAssetId === row.asset.id}
              key={row.asset.id}
              onSelect={onSelectAsset}
            />
          ),
        )}
      </ul>
    </div>
  )
}

function FindingInventoryTreeNode({
  asset,
  isSelected,
  onSelect,
}: {
  asset: Asset
  isSelected: boolean
  onSelect: (assetId: string) => void
}) {
  const Icon =
    asset.type === folderType ? Folder : asset.type === scanTargetType ? PackageSearch : Box

  return (
    <li>
      <button
        aria-current={isSelected ? "true" : undefined}
        className={cn(
          "grid min-h-12 w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
          isSelected && "bg-accent text-accent-foreground",
        )}
        onClick={() => onSelect(asset.id)}
        type="button"
      >
        <span className="flex min-w-0 items-center gap-2">
          <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span className="min-w-0">
            <span className="block truncate font-medium">{asset.name}</span>
            <span className="block truncate text-xs text-muted-foreground">{asset.path}</span>
          </span>
        </span>
        <Badge variant={asset.type === scanTargetType ? "default" : "outline"}>
          {assetBadgeLabel(asset)}
        </Badge>
      </button>
    </li>
  )
}

function assetBadgeLabel(asset: Asset): string {
  return asset.scan_label ?? assetTypeLabel(asset.type)
}

function assetTypeLabel(type: string): string {
  if (type === scanTargetType) {
    return "Asset"
  }
  return titleCaseLabel(type.replaceAll("_", " "))
}

function titleCaseLabel(value: string): string {
  return value
    .split(" ")
    .filter(Boolean)
    .map((word) => `${word.charAt(0).toLocaleUpperCase()}${word.slice(1).toLocaleLowerCase()}`)
    .join(" ")
}

function Field({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <label className="grid gap-1.5 text-xs font-medium text-muted-foreground">
      <span>{label}</span>
      {children}
    </label>
  )
}

function Select({
  children,
  disabled = false,
  onChange,
  value,
}: {
  children: React.ReactNode
  disabled?: boolean
  onChange: (value: string) => void
  value: string
}) {
  return (
    <select
      className="flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-60 focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      value={value}
    >
      {children}
    </select>
  )
}

function FindingsTable({
  direction,
  isError,
  isLoading,
  onSelect,
  onSort,
  rows,
  selectedFindingId,
  sort,
}: {
  direction: SortDirection
  isError: boolean
  isLoading: boolean
  onSelect: (id: string) => void
  onSort: (sort: FindingSortKey) => void
  rows: FindingRow[]
  selectedFindingId: string | null
  sort: FindingSortKey
}) {
  if (isLoading) {
    return <StateMessage label="Loading findings..." />
  }

  if (isError) {
    return <StateMessage label="Unable to load findings from the backend API." tone="error" />
  }

  if (rows.length === 0) {
    return <StateMessage label="No findings match these filters." />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[72rem] border-collapse text-left text-sm">
        <thead className="bg-muted/60 text-xs uppercase text-muted-foreground">
          <tr>
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Identifier"
              onSort={onSort}
              sort="identifier"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Severity"
              onSort={onSort}
              sort="severity"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Package"
              onSort={onSort}
              sort="package"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Installed"
              onSort={onSort}
              sort="installed_version"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Fixed"
              onSort={onSort}
              sort="fixed_version"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Project / asset"
              onSort={onSort}
              sort="project"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Status"
              onSort={onSort}
              sort="status"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="SLA"
              onSort={onSort}
              sort="sla_remaining"
            />
            <SortableTh
              activeDirection={direction}
              activeSort={sort}
              label="Grace"
              onSort={onSort}
              sort="grace_remaining"
            />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              className={cn(
                "border-t transition-colors hover:bg-accent/60",
                selectedFindingId === row.id && "bg-accent",
              )}
              key={row.id}
            >
              <Td>
                <button
                  aria-label={`View details for ${row.primary_identifier}`}
                  className="block max-w-full truncate rounded-sm text-left font-medium text-primary underline-offset-4 outline-none hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50"
                  onClick={() => onSelect(row.id)}
                  type="button"
                >
                  {row.primary_identifier}
                </button>
                {row.additional_identifiers.length > 0 ? (
                  <div className="mt-1 truncate text-xs text-muted-foreground">
                    {row.additional_identifiers.join(", ")}
                  </div>
                ) : null}
              </Td>
              <Td>
                <SeverityBadge severity={row.severity} />
              </Td>
              <Td>{emptyFallback(row.package_name)}</Td>
              <Td>{emptyFallback(row.installed_version)}</Td>
              <Td>{emptyFallback(row.fixed_version)}</Td>
              <Td>
                <div className="font-medium">{row.project_name}</div>
                <div className="mt-1 truncate text-xs text-muted-foreground">
                  {row.scan_target_name} · {row.scan_target_path}
                </div>
              </Td>
              <Td>
                <Badge variant={row.status === "open" ? "default" : "outline"}>
                  {formatStatus(row.status)}
                </Badge>
              </Td>
              <Td>{daysLabel(row.sla_remaining_days)}</Td>
              <Td>{daysLabel(row.grace_remaining_days)}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FindingDrawer({
  currentActor,
  detail,
  error,
  isError,
  isLoading,
  isMinimized,
  onClose,
  onMinimize,
  onRestore,
  projects,
  selectedFindingId,
}: {
  currentActor: ActorMetadata
  detail: FindingDetail | null
  error: Error | null
  isError: boolean
  isLoading: boolean
  isMinimized: boolean
  onClose: () => void
  onMinimize: () => void
  onRestore: () => void
  projects: Project[]
  selectedFindingId: string | null
}) {
  const title = detail?.primary_identifier ?? "Finding Detail"
  const subtitle = detail
    ? `${emptyFallback(detail.package_name)} on ${detail.project_name} / ${detail.scan_target_name}`
    : selectedFindingId
      ? "Loading finding detail"
      : "No finding selected"

  if (selectedFindingId === null) {
    return null
  }

  return (
    <div className="pointer-events-none fixed inset-0 z-40">
      <Card
        aria-hidden={isMinimized}
        aria-label="Finding detail drawer"
        className={cn(
          "pointer-events-auto fixed inset-y-0 right-0 flex w-full max-w-full translate-x-0 flex-col overflow-hidden rounded-none border-y-0 border-r-0 py-0 shadow-2xl transition-transform duration-300 ease-out sm:inset-y-3 sm:right-3 sm:w-[min(60rem,calc(100vw-3rem))] sm:rounded-lg sm:border",
          isMinimized && "translate-x-[calc(100%+1rem)]",
        )}
        inert={isMinimized ? true : undefined}
        role="dialog"
      >
        <CardHeader className="min-h-20 shrink-0 border-b px-6 py-4">
          <div className="flex min-w-0 items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-2">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
              <div className="min-w-0">
                <CardTitle className="break-words text-base">{title}</CardTitle>
                <CardDescription className="mt-1 break-words">{subtitle}</CardDescription>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <Button
                aria-label="Minimize finding detail"
                onClick={onMinimize}
                size="icon"
                type="button"
                variant="ghost"
              >
                <PanelRightClose aria-hidden="true" />
              </Button>
              <Button
                aria-label="Close finding detail"
                onClick={onClose}
                size="icon"
                type="button"
                variant="ghost"
              >
                <X aria-hidden="true" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <div className="min-h-0 flex-1 overflow-y-auto">
          <DetailPanel
            currentActor={currentActor}
            detail={detail}
            error={error}
            isError={isError}
            isLoading={isLoading}
            projects={projects}
            selectedFindingId={selectedFindingId}
          />
        </div>
      </Card>
      <Button
        aria-label="Restore finding detail"
        className={cn(
          "pointer-events-auto fixed right-2 top-1/2 z-50 h-auto min-h-28 w-10 -translate-y-1/2 translate-x-16 flex-col gap-2 rounded-r-none px-2 py-3 shadow-lg transition-transform duration-300 ease-out sm:right-0",
          isMinimized && "translate-x-0",
        )}
        onClick={onRestore}
        type="button"
      >
        <PanelRightOpen className="size-4" aria-hidden="true" />
        <span className="[writing-mode:vertical-rl]">Detail</span>
      </Button>
    </div>
  )
}

function DetailPanel({
  currentActor,
  detail,
  error,
  isError,
  isLoading,
  projects,
  selectedFindingId,
}: {
  currentActor: ActorMetadata
  detail: FindingDetail | null
  error: Error | null
  isError: boolean
  isLoading: boolean
  projects: Project[]
  selectedFindingId: string
}) {
  const queryClient = useQueryClient()
  const [commentBody, setCommentBody] = useState("")
  const [statusTarget, setStatusTarget] = useState<FindingStatus>("open")
  const [statusReason, setStatusReason] = useState("")
  const [requirePeerReview, setRequirePeerReview] = useState(false)

  useEffect(() => {
    if (detail) {
      setStatusTarget(detail.status)
      setStatusReason("")
      setRequirePeerReview(false)
    }
    setCommentBody("")
  }, [detail?.id, detail?.status])

  const commentMutation = useMutation({
    mutationFn: ({ findingId, body }: { findingId: string; body: string }) =>
      createFindingComment(findingId, { body }),
    onSuccess: (comment, variables) => {
      setCommentBody("")
      queryClient.setQueryData<FindingDetail>(["findings", variables.findingId], (current) =>
        current
          ? {
              ...current,
              comments: [...current.comments, comment].sort(compareByCreatedAt),
            }
          : current,
      )
      void queryClient.invalidateQueries({ queryKey: ["findings"] })
    },
  })

  const statusMutation = useMutation({
    mutationFn: ({
      findingId,
      reason,
      requireReview,
      status,
    }: {
      findingId: string
      reason: string
      requireReview: boolean
      status: FindingStatus
    }) =>
      updateFindingStatus(findingId, {
        status,
        comment: reason,
        require_peer_review: requireReview,
      }),
    onSuccess: (updatedDetail) => {
      setStatusTarget(updatedDetail.status)
      setStatusReason("")
      setRequirePeerReview(false)
      queryClient.setQueryData(["findings", updatedDetail.id], updatedDetail)
      void queryClient.invalidateQueries({ queryKey: ["findings"] })
    },
  })

  if (isLoading) {
    return (
      <div className="p-5">
        <StateMessage label="Loading detail..." />
      </div>
    )
  }

  if (isError || detail === null) {
    return (
      <div className="p-5">
        <div className="rounded-md border bg-card p-4">
          <div className="flex items-center gap-2">
            <AlertCircle className="size-4 text-destructive" aria-hidden="true" />
            <h2 className="text-base font-semibold">Unable to load detail</h2>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            {error?.message ?? "The backend API did not return this finding."}
          </p>
        </div>
      </div>
    )
  }

  const trimmedComment = commentBody.trim()
  const trimmedReason = statusReason.trim()
  const requiresReason = statusTarget !== detail.status && statusTarget !== "open"
  const requireReview = effectiveStatusPeerReviewRequired(detail, projects, requirePeerReview)
  const peerReviewControl = statusPeerReviewControlState(detail, projects, requirePeerReview)
  const canSubmitStatus =
    statusTarget !== detail.status &&
    (!requiresReason || trimmedReason.length > 0) &&
    !statusMutation.isPending
  const commentActivity = buildCommentsActivity(detail.comments, detail.status_change_requests)
  const activity = buildActivity(detail.comments, detail.status_change_requests, detail)

  return (
    <CardContent className="space-y-5 p-5 text-sm">
      <dl className="grid grid-cols-2 gap-3">
        <DetailTerm label="Severity" value={formatSeverity(detail.severity)} />
        <DetailTerm label="Status" value={formatStatus(detail.status)} />
        <DetailTerm label="Installed" value={emptyFallback(detail.installed_version)} />
        <DetailTerm label="Fixed" value={emptyFallback(detail.fixed_version)} />
        <DetailTerm label="Vulnerability SLA" value={daysLabel(detail.sla_remaining_days)} />
        <DetailTerm label="Grace" value={daysLabel(detail.grace_remaining_days)} />
      </dl>

      <DetailSection title="Evidence">
        <div className="space-y-2 rounded-md border bg-muted/40 p-3">
          <p className="text-muted-foreground">Description</p>
          <p className="whitespace-pre-wrap break-words">
            {emptyFallback(descriptionForFindingDetail(detail))}
          </p>
        </div>
        <div className="space-y-2 rounded-md border bg-muted/40 p-3">
          <p>
            <span className="text-muted-foreground">Scanner ID:</span>{" "}
            {detail.scanner_finding_id}
          </p>
          <p>
            <span className="text-muted-foreground">Artifact:</span>{" "}
            {emptyFallback([detail.artifact_name, detail.artifact_type, detail.artifact_path].filter(Boolean).join(" · "))}
          </p>
          <p>
            <span className="text-muted-foreground">Source:</span>{" "}
            {sourceSummary(detail.source_evidence)}
          </p>
        </div>
      </DetailSection>

      <DetailSection title="References">
        {detail.references.length === 0 ? (
          <p className="text-muted-foreground">No references provided.</p>
        ) : (
          <ul className="space-y-2">
            {detail.references.map((reference) => (
              <li key={reference}>
                <Reference reference={reference} />
              </li>
            ))}
          </ul>
        )}
      </DetailSection>

      <DetailSection title="Comments / Activity">
        {commentActivity.length === 0 ? (
          <p className="rounded-md border bg-muted/30 p-3 text-muted-foreground">
            No comments yet.
          </p>
        ) : (
          <ol className="space-y-2">
            {commentActivity.map((item) => (
              <li className="rounded-md border bg-muted/30 p-3" key={item.id}>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{item.actor}</span>
                  {item.badge ? <Badge variant="outline">{item.badge}</Badge> : null}
                  <span>{formatDateTime(item.createdAt)}</span>
                </div>
                {item.transition ? (
                  <div className="mt-1 text-xs font-medium">
                    {formatStatus(item.transition.from)} {"->"} {formatStatus(item.transition.to)}
                  </div>
                ) : null}
                {item.body ? (
                  <p className="mt-1 whitespace-pre-wrap break-words">{item.body}</p>
                ) : null}
                <ActivityDecisionSummary item={item} />
                {selectedFindingId && item.request && isPendingStatusRequest(item.request) ? (
                  <StatusRequestReviewForm
                    currentActor={currentActor}
                    findingId={selectedFindingId}
                    request={item.request}
                  />
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </DetailSection>

      <DetailSection title="Add Comment">
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault()
            if (!selectedFindingId || !trimmedComment) {
              return
            }
            commentMutation.mutate({ findingId: selectedFindingId, body: trimmedComment })
          }}
        >
          <Textarea
            disabled={commentMutation.isPending}
            onChange={(event) => setCommentBody(event.target.value)}
            placeholder="Add a concise note"
            value={commentBody}
          />
          <MutationError error={commentMutation.error} />
          <div className="flex justify-end">
            <Button
              disabled={commentMutation.isPending || !trimmedComment}
              size="sm"
              type="submit"
            >
              {commentMutation.isPending ? "Adding..." : "Add comment"}
            </Button>
          </div>
        </form>
      </DetailSection>

      <DetailSection title="Status Workflow">
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault()
            if (!selectedFindingId || !canSubmitStatus) {
              return
            }
            statusMutation.mutate({
              findingId: selectedFindingId,
              reason: trimmedReason,
              requireReview,
              status: statusTarget,
            })
          }}
        >
          <Field label="Target status">
            <Select
              onChange={(value) => setStatusTarget(value as FindingStatus)}
              value={statusTarget}
            >
              {statuses.map((status) => (
                <option key={status.value} value={status.value}>
                  {status.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={requiresReason ? "Reason required" : "Reason"}>
            <Textarea
              disabled={statusMutation.isPending}
              onChange={(event) => setStatusReason(event.target.value)}
              placeholder="Why is this status changing?"
              value={statusReason}
            />
          </Field>
          <label className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            <input
              checked={peerReviewControl.checked}
              className="size-4 rounded border"
              disabled={statusMutation.isPending || peerReviewControl.disabled}
              onChange={(event) => setRequirePeerReview(event.target.checked)}
              type="checkbox"
            />
            <span>{peerReviewControl.label}</span>
          </label>
          {peerReviewControl.disabled ? (
            <p className="text-xs text-muted-foreground">
              Project or global policy requires review for this status change.
            </p>
          ) : null}
          {requiresReason && !trimmedReason ? (
            <p className="text-xs text-muted-foreground">
              Add a reason before changing to this status.
            </p>
          ) : null}
          <MutationError error={statusMutation.error} />
          <div className="flex justify-end">
            <Button disabled={!canSubmitStatus} size="sm" type="submit">
              {statusSubmitLabel(statusMutation.isPending, requireReview)}
            </Button>
          </div>
        </form>
      </DetailSection>

      <DetailSection title="Vulnerability Changelog">
        {activity.length === 0 ? (
          <p className="rounded-md border bg-muted/30 p-3 text-muted-foreground">
            No lifecycle events yet.
          </p>
        ) : (
          <ol className="space-y-2">
            {activity.map((item) => (
              <li className="rounded-md border bg-muted/30 p-3" key={`log-${item.id}`}>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{item.actor}</span>
                  {item.badge ? <Badge variant="outline">{item.badge}</Badge> : null}
                  <span>{formatDateTime(item.createdAt)}</span>
                </div>
                {item.transition ? (
                  <div className="mt-1 text-xs font-medium">
                    {formatStatus(item.transition.from)} {"->"} {formatStatus(item.transition.to)}
                  </div>
                ) : null}
                {item.body ? (
                  <p className="mt-1 whitespace-pre-wrap break-words">{item.body}</p>
                ) : null}
                <ActivityDecisionSummary item={item} />
              </li>
            ))}
          </ol>
        )}
      </DetailSection>
    </CardContent>
  )
}

type ActivityItem = {
  id: string
  actor: string
  badge: string | null
  body: string | null
  createdAt: string
  decisionActor: string | null
  decisionBody: string | null
  request: FindingStatusChangeRequest | null
  transition: { from: FindingStatus; to: FindingStatus } | null
}

export function buildActivity(
  comments: FindingComment[],
  requests: FindingStatusChangeRequest[],
  detail?: FindingDetail,
): ActivityItem[] {
  const pairedCommentIds = new Set<string>()
  const requestActivity = requests.map((request): ActivityItem => {
    const pairedComment = comments.find((comment) =>
      isMatchingStatusRequestComment(comment, request, pairedCommentIds),
    )

    if (pairedComment) {
      pairedCommentIds.add(pairedComment.id)
    }

    return {
      id: `status-request-${request.id}`,
      actor: displayPrincipalLabel(
        request.requester_display,
        request.requester_principal_type,
        request.requester_principal_id,
      ),
      badge: `Request ${formatRequestState(request.state)}`,
      body: request.comment,
      createdAt: request.created_at,
      decisionActor: displayNullablePrincipalLabel(
        request.reviewer_display,
        request.reviewer_principal_type,
        request.reviewer_principal_id,
      ),
      decisionBody: request.decision_comment,
      request,
      transition: { from: request.from_status, to: request.to_status },
    }
  })

  const lifecycleActivity = detail ? findingLifecycleActivity(detail) : []
  return [
    ...lifecycleActivity,
    ...requestActivity,
  ].sort(compareByCreatedAt)
}

export function buildCommentsActivity(
  comments: FindingComment[],
  requests: FindingStatusChangeRequest[],
): ActivityItem[] {
  const pairedCommentIds = new Set<string>()
  for (const request of requests) {
    const pairedComment = comments.find((comment) =>
      isMatchingStatusRequestComment(comment, request, pairedCommentIds),
    )
    if (pairedComment) {
      pairedCommentIds.add(pairedComment.id)
    }
  }

  return [
    ...requests.filter(isPendingStatusRequest).map((request): ActivityItem => ({
      id: `status-request-${request.id}`,
      actor: displayPrincipalLabel(
        request.requester_display,
        request.requester_principal_type,
        request.requester_principal_id,
      ),
      badge: `Request ${formatRequestState(request.state)}`,
      body: request.comment,
      createdAt: request.created_at,
      decisionActor: null,
      decisionBody: null,
      request,
      transition: { from: request.from_status, to: request.to_status },
    })),
    ...comments
      .filter(
        (comment) =>
          !pairedCommentIds.has(comment.id) &&
          !comment.is_system &&
          !(comment.status_from && comment.status_to),
      )
      .map((comment): ActivityItem => ({
        id: `comment-${comment.id}`,
        actor: displayPrincipalLabel(
          comment.author_display,
          comment.author_principal_type,
          comment.author_principal_id,
        ),
        badge: "Comment",
        body: comment.body || null,
        createdAt: comment.created_at,
        decisionActor: null,
        decisionBody: null,
        request: null,
        transition: null,
      })),
  ].sort(compareByCreatedAt)
}

export function effectiveStatusPeerReviewRequired(
  detail: FindingDetail,
  projects: Project[],
  requestedPeerReview: boolean,
): boolean {
  return statusPeerReviewRequiredByPolicy(detail, projects) || requestedPeerReview
}

export function statusPeerReviewControlState(
  detail: FindingDetail,
  projects: Project[],
  requestedPeerReview: boolean,
): { checked: boolean; disabled: boolean; label: string } {
  const requiredByPolicy = statusPeerReviewRequiredByPolicy(detail, projects)
  return {
    checked: requiredByPolicy || requestedPeerReview,
    disabled: requiredByPolicy,
    label: requiredByPolicy ? "Peer review required" : "Require peer review",
  }
}

function statusPeerReviewRequiredByPolicy(detail: FindingDetail, projects: Project[]): boolean {
  return (
    detail.peer_review_required_for_status_changes ||
    projects.some(
      (project) =>
        project.id === detail.project_id && project.require_peer_review_for_status_changes,
    )
  )
}

export function statusSubmitLabel(isPending: boolean, requirePeerReview: boolean): string {
  if (isPending) {
    return requirePeerReview ? "Requesting..." : "Changing..."
  }
  return requirePeerReview ? "Request" : "Change"
}

export function decisionSummaryForActivity(item: ActivityItem | undefined): string | null {
  if (!item?.decisionBody) {
    return null
  }
  return `Decision${item.decisionActor ? ` by ${item.decisionActor}` : ""}: ${item.decisionBody}`
}

function ActivityDecisionSummary({ item }: { item: ActivityItem }) {
  const decisionSummary = decisionSummaryForActivity(item)
  if (!decisionSummary) {
    return null
  }
  return (
    <p className="mt-1 whitespace-pre-wrap break-words text-muted-foreground">
      {decisionSummary}
    </p>
  )
}

function findingLifecycleActivity(detail: FindingDetail): ActivityItem[] {
  const activity: ActivityItem[] = [
    {
      id: `import-${detail.id}`,
      actor: "System",
      badge: "Import",
      body: "Finding imported from scanner report.",
      createdAt: detail.first_detected_at,
      decisionActor: null,
      decisionBody: null,
      request: null,
      transition: null,
    },
  ]
  const enrichmentLinks = enrichmentReferenceCount(detail)
  if (enrichmentLinks > 0) {
    activity.push({
      id: `hydration-${detail.id}`,
      actor: "System",
      badge: "Hydration",
      body: `Hydrated vulnerability evidence with ${enrichmentLinks} reference${enrichmentLinks === 1 ? "" : "s"}.`,
      createdAt: detail.last_seen_at,
      decisionActor: null,
      decisionBody: null,
      request: null,
      transition: null,
    })
  }
  return activity
}

function enrichmentReferenceCount(detail: FindingDetail): number {
  const enrichment = detail.source_evidence.enrichment
  if (
    enrichment &&
    typeof enrichment === "object" &&
    "cve_source_links" in enrichment &&
    Array.isArray(enrichment.cve_source_links)
  ) {
    return enrichment.cve_source_links.length
  }
  return 0
}

export function descriptionForFindingDetail(detail: FindingDetail): string | null {
  const directDescription = detail.description?.trim()
  if (directDescription) {
    return directDescription
  }
  const sourceDescription = detail.source_evidence.description
  if (typeof sourceDescription === "string" && sourceDescription.trim()) {
    return sourceDescription.trim()
  }
  const sourceTitle = detail.source_evidence.title
  if (typeof sourceTitle === "string" && sourceTitle.trim()) {
    return sourceTitle.trim()
  }
  return null
}

function StatusRequestReviewForm({
  currentActor,
  findingId,
  request,
}: {
  currentActor: ActorMetadata
  findingId: string
  request: FindingStatusChangeRequest
}) {
  const queryClient = useQueryClient()
  const [decisionComment, setDecisionComment] = useState("")
  const [localError, setLocalError] = useState<string | null>(null)
  const trimmedDecisionComment = decisionComment.trim()
  const isRequester = isSamePrincipal(
    currentActor.principal_type,
    currentActor.principal_id,
    request.requester_principal_type,
    request.requester_principal_id,
  )

  const reviewMutation = useMutation({
    mutationFn: ({
      action,
      comment,
    }: {
      action: "approve" | "reject"
      comment: string
    }) => {
      if (action === "approve") {
        return approveFindingStatusRequest(findingId, request.id, comment ? { comment } : {})
      }
      return rejectFindingStatusRequest(findingId, request.id, { comment })
    },
    onSuccess: (updatedDetail) => {
      setDecisionComment("")
      setLocalError(null)
      queryClient.setQueryData(["findings", updatedDetail.id], updatedDetail)
      void queryClient.invalidateQueries({ queryKey: ["findings"] })
    },
  })

  const submitDecision = (action: "approve" | "reject") => {
    setLocalError(null)
    if (action === "reject" && !trimmedDecisionComment) {
      setLocalError("Add a decision comment before rejecting this request.")
      return
    }
    reviewMutation.mutate({ action, comment: trimmedDecisionComment })
  }

  const retractMutation = useMutation({
    mutationFn: () => retractFindingStatusRequest(findingId, request.id),
    onSuccess: (updatedDetail) => {
      queryClient.setQueryData(["findings", updatedDetail.id], updatedDetail)
      void queryClient.invalidateQueries({ queryKey: ["findings"] })
    },
  })

  return (
    <div className="mt-3 space-y-3 rounded-md border bg-background p-3">
      <div>
        <div className="text-xs font-medium text-foreground">
          Pending review for {formatStatus(request.to_status)}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {isRequester
            ? "Another reviewer must approve this request."
            : "Review this requested status change for another user."}
        </p>
      </div>
      {isRequester ? (
        <>
          <MutationError error={retractMutation.error} />
          <div className="flex justify-end">
            <Button
              disabled={retractMutation.isPending}
              onClick={() => retractMutation.mutate()}
              size="sm"
              type="button"
              variant="outline"
            >
              {retractMutation.isPending ? "Retracting..." : "Retract request"}
            </Button>
          </div>
        </>
      ) : (
        <>
          <Textarea
            disabled={reviewMutation.isPending}
            onChange={(event) => {
              setDecisionComment(event.target.value)
              if (localError) {
                setLocalError(null)
              }
            }}
            placeholder="Decision comment"
            value={decisionComment}
          />
          {localError ? (
            <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {localError}
            </p>
          ) : null}
          <MutationError error={reviewMutation.error} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              disabled={reviewMutation.isPending}
              onClick={() => submitDecision("approve")}
              size="sm"
              type="button"
              variant="outline"
            >
              {reviewMutation.isPending ? "Reviewing..." : "Approve"}
            </Button>
            <Button
              disabled={reviewMutation.isPending}
              onClick={() => submitDecision("reject")}
              size="sm"
              type="button"
              variant="destructive"
            >
              {reviewMutation.isPending ? "Reviewing..." : "Reject"}
            </Button>
          </div>
        </>
      )}
    </div>
  )
}

function isPendingStatusRequest(request: FindingStatusChangeRequest): boolean {
  return request.state.toLowerCase() === "pending"
}

function isSamePrincipal(
  leftType: string,
  leftId: string,
  rightType: string,
  rightId: string,
): boolean {
  return leftType === rightType && leftId === rightId
}

function isMatchingStatusRequestComment(
  comment: FindingComment,
  request: FindingStatusChangeRequest,
  pairedCommentIds: Set<string>,
): boolean {
  if (
    pairedCommentIds.has(comment.id) ||
    comment.status_from !== request.from_status ||
    comment.status_to !== request.to_status
  ) {
    return false
  }

  return normalizeActivityBody(comment.body) === normalizeActivityBody(request.comment)
}

function normalizeActivityBody(value: string | null): string {
  return (value ?? "").trim().replace(/\s+/g, " ")
}

function compareByCreatedAt(
  left: { createdAt?: string; created_at?: string },
  right: { createdAt?: string; created_at?: string },
): number {
  const leftDate = Date.parse(left.createdAt ?? left.created_at ?? "")
  const rightDate = Date.parse(right.createdAt ?? right.created_at ?? "")
  return leftDate - rightDate
}

function principalLabel(type: string, id: string): string {
  return `${formatPrincipalType(type)}:${id}`
}

function displayPrincipalLabel(display: string | null, type: string, id: string): string {
  return display || principalLabel(type, id)
}

function displayNullablePrincipalLabel(
  display: string | null,
  type: string | null,
  id: string | null,
): string | null {
  if (display) {
    return display
  }
  if (type && id) {
    return principalLabel(type, id)
  }
  return null
}

function formatPrincipalType(type: string): string {
  return type
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ")
}

function formatRequestState(state: string): string {
  return state
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ")
}

function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function MutationError({ error }: { error: Error | null }) {
  if (!error) {
    return null
  }
  return (
    <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
      {error.message || "The request failed."}
    </p>
  )
}

function Reference({ reference }: { reference: string }) {
  if (!isSafeReferenceUrl(reference)) {
    return <span className="block max-w-full break-words text-muted-foreground">{reference}</span>
  }

  return (
    <a
      className="inline-flex max-w-full items-center gap-2 text-primary underline-offset-4 hover:underline"
      href={reference}
      rel="noreferrer"
      target="_blank"
    >
      <span className="truncate">{reference}</span>
      <ExternalLink className="size-3.5 shrink-0" aria-hidden="true" />
    </a>
  )
}

function isSafeReferenceUrl(reference: string): boolean {
  try {
    const url = new URL(reference)
    return url.protocol === "http:" || url.protocol === "https:"
  } catch {
    return false
  }
}

export function nextFindingTableSort(
  currentSort: FindingSortKey,
  currentDirection: SortDirection,
  selectedSort: FindingSortKey,
): FindingTableSort {
  if (currentSort === selectedSort) {
    return {
      sort: selectedSort,
      direction: currentDirection === "asc" ? "desc" : "asc",
    }
  }
  return {
    sort: selectedSort,
    direction: sortDirectionForNewFindingColumn(selectedSort),
  }
}

export function sortDirectionForNewFindingColumn(sort: FindingSortKey): SortDirection {
  if (sort === "severity" || sort === "last_seen" || sort === "first_detected") {
    return "desc"
  }
  if (sort === "sla_remaining" || sort === "grace_remaining") {
    return "asc"
  }
  return "asc"
}

export function findingFiltersFromSearchParams(searchParams: URLSearchParams): Filters {
  const severity = searchParams.get("severity")?.trim().toUpperCase() ?? ""
  const status = searchParams.get("status")?.trim() ?? ""
  const fixAvailable = searchParams.get("fix_available")?.trim() ?? ""
  const presentInLatestScan = searchParams.get("present_in_latest_scan")?.trim() ?? ""
  const sort = searchParams.get("sort")?.trim() ?? ""
  const direction = searchParams.get("direction")?.trim() ?? ""

  return {
    ...defaultFindingFilters,
    severity: severities.includes(severity) ? severity : "",
    status: isFindingStatus(status) ? status : "",
    identifier: safeSearchParam(searchParams.get("identifier")),
    packageName: safeSearchParam(searchParams.get("package")),
    presentInLatestScan: isBooleanFilter(presentInLatestScan)
      ? presentInLatestScan
      : defaultFindingFilters.presentInLatestScan,
    fixAvailable: isBooleanFilter(fixAvailable)
      ? fixAvailable
      : defaultFindingFilters.fixAvailable,
    sort: isFindingSortKey(sort) ? sort : defaultFindingFilters.sort,
    direction: direction === "asc" || direction === "desc" ? direction : defaultFindingFilters.direction,
  }
}

export function findingInventoryScopeFromSearchParams(
  searchParams: URLSearchParams,
): FindingInventoryScope {
  return {
    projectId: safeOpaqueIdParam(searchParams.get("project_id")),
    assetId: safeOpaqueIdParam(searchParams.get("asset_id")),
  }
}

function safeSearchParam(value: string | null): string {
  return (value ?? "").trim().slice(0, 128)
}

function safeOpaqueIdParam(value: string | null): string {
  const candidate = (value ?? "").trim()
  return /^[A-Za-z0-9_-]{1,128}$/.test(candidate) ? candidate : ""
}

function isBooleanFilter(value: string): value is "all" | "true" | "false" {
  return value === "all" || value === "true" || value === "false"
}

function isFindingStatus(value: string): value is FindingStatus {
  return statuses.some((status) => status.value === value)
}

function isFindingSortKey(value: string): value is FindingSortKey {
  return sortOptions.some((option) => option.value === value)
}

function SortableTh({
  activeDirection,
  activeSort,
  label,
  onSort,
  sort,
}: {
  activeDirection: SortDirection
  activeSort: FindingSortKey
  label: string
  onSort: (sort: FindingSortKey) => void
  sort: FindingSortKey
}) {
  const isActive = activeSort === sort
  const Icon = isActive ? (activeDirection === "asc" ? ArrowUp : ArrowDown) : ArrowUpDown
  return (
    <Th ariaSort={isActive ? (activeDirection === "asc" ? "ascending" : "descending") : "none"}>
      <button
        aria-label={`Sort by ${label} ${isActive && activeDirection === "asc" ? "descending" : "ascending"}`}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-sm text-left uppercase outline-none transition-colors hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50",
          isActive && "text-foreground",
        )}
        onClick={() => onSort(sort)}
        type="button"
      >
        <span>{label}</span>
        <Icon className="size-3.5" aria-hidden="true" />
      </button>
    </Th>
  )
}

function Th({
  ariaSort,
  children,
}: {
  ariaSort?: "ascending" | "descending" | "none"
  children: React.ReactNode
}) {
  return (
    <th aria-sort={ariaSort} className="px-3 py-2 font-semibold">
      {children}
    </th>
  )
}

function Td({ children }: { children: React.ReactNode }) {
  return <td className="max-w-[14rem] px-3 py-3 align-top">{children}</td>
}

function StateMessage({ label, tone = "muted" }: { label: string; tone?: "muted" | "error" }) {
  return (
    <div
      className={cn(
        "flex min-h-44 items-center justify-center px-4 text-sm",
        tone === "error" ? "text-destructive" : "text-muted-foreground",
      )}
    >
      {label}
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toUpperCase()
  return (
    <Badge className={severityPillClassName(normalized)} variant="outline">
      {formatSeverity(normalized)}
    </Badge>
  )
}

function DetailSection({ children, title }: { children: React.ReactNode; title: string }) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase text-muted-foreground">{title}</h3>
      {children}
    </section>
  )
}

function DetailTerm({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-medium">{value}</dd>
    </div>
  )
}

export function resultLabel(
  isLoading: boolean,
  count: number,
  scopeLabel = "the entire inventory",
): string {
  if (isLoading) {
    return "Loading..."
  }
  return `${new Intl.NumberFormat().format(count)} finding${count === 1 ? "" : "s"} in ${scopeLabel}`
}

function emptyFallback(value: string | null): string {
  return value && value.trim() ? value : "None"
}

function daysLabel(value: number | null): string {
  if (value === null) {
    return "Not active"
  }
  if (value < 0) {
    return `${Math.abs(value)}d overdue`
  }
  if (value === 0) {
    return "Due today"
  }
  return `${value}d`
}

function formatStatus(status: FindingStatus): string {
  return statuses.find((item) => item.value === status)?.label ?? status
}

function formatSeverity(severity: string): string {
  return severity
    .toLowerCase()
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ")
}

function sourceSummary(source: Record<string, unknown>): string {
  const resultClass = source.result_class
  const target = source.target
  const parts = [resultClass, target].filter((value): value is string => typeof value === "string")
  if (parts.length > 0) {
    return parts.join(" · ")
  }
  return `${Object.keys(source).length} source field${Object.keys(source).length === 1 ? "" : "s"}`
}
