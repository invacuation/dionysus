import { AlertCircle, CheckCircle2, FileUp, Info, Upload } from "lucide-react"
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
import {
  ApiError,
  importTrivyReport,
  listProjectAssets,
  listProjects,
  previewTrivyReport,
  type Asset,
  type ImportTrivyReportResponse,
  type Project,
  type TrivyImportPreviewResponse,
} from "@/lib/api"
import { cn } from "@/lib/utils"

const scanTargetType = "scan_target"
const folderType = "folder"
const pendingImportAssetId = "__pending_import_asset__"
const pendingImportFolderIdPrefix = "__pending_import_folder__:"

export function ImportsPage() {
  const queryClient = useQueryClient()
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [folderPath, setFolderPath] = useState("")
  const [assetName, setAssetName] = useState("")
  const [targetRef, setTargetRef] = useState("")
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileInputKey, setFileInputKey] = useState(0)
  const [scanStartedAt, setScanStartedAt] = useState("")
  const [isDraggingFile, setIsDraggingFile] = useState(false)

  const projectsQuery = useQuery({
    queryKey: ["projects"],
    queryFn: listProjects,
  })

  const projects = projectsQuery.data?.projects ?? []

  useEffect(() => {
    if (!selectedProjectId && projects.length > 0) {
      setSelectedProjectId(projects[0].id)
    }
    if (selectedProjectId && !projects.some((project) => project.id === selectedProjectId)) {
      setSelectedProjectId(projects[0]?.id ?? "")
    }
  }, [projects, selectedProjectId])

  const assetsQuery = useQuery({
    queryKey: ["projects", selectedProjectId, "assets"],
    queryFn: () => listProjectAssets(selectedProjectId),
    enabled: selectedProjectId.length > 0,
  })

  const assets = assetsQuery.data?.assets ?? []
  const folders = useMemo(() => folderOptionsForImport(assets), [assets])
  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null
  const pendingFolders = useMemo(
    () => pendingImportFolders(folders, folderPath),
    [folders, folderPath],
  )
  const selectedFolder = folderForImportPath([...folders, ...pendingFolders], folderPath)

  const previewMutation = useMutation({
    mutationFn: previewTrivyReport,
    onSuccess: (preview) => {
      setFolderPath((current) => current || preview.detected_project_name || "")
      setAssetName((current) => current || preview.detected_asset_name || "")
      setTargetRef((current) => current || preview.detected_target_ref || "")
      setScanStartedAt((current) => current || datetimeLocalFromIso(preview.scan_started_at))
    },
  })

  const importMutation = useMutation({
    mutationFn: importTrivyReport,
    onSuccess: async () => {
      setSelectedFile(null)
      setAssetName("")
      setTargetRef("")
      setScanStartedAt("")
      setFileInputKey((currentKey) => currentKey + 1)
      previewMutation.reset()
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["overview"] }),
        queryClient.invalidateQueries({ queryKey: ["findings"] }),
        queryClient.invalidateQueries({ queryKey: ["projects", selectedProjectId, "assets"] }),
      ])
    },
  })

  const preview = previewMutation.data ?? null
  const canUpload = canUploadReport({
    hasProject: selectedProjectId.length > 0,
    folderPath,
    file: selectedFile,
    hasSuccessfulPreview: previewMutation.isSuccess,
    isUploading: importMutation.isPending,
  })
  const pendingAsset = pendingImportAsset(selectedFolder, assetName, targetRef, preview)

  function uploadReport() {
    const normalizedFolderPath = normalizeImportFolderPath(folderPath)
    if (!selectedFile || !selectedProjectId) {
      return
    }
    importMutation.mutate({
      project_id: selectedProjectId,
      folder_path: normalizedFolderPath,
      asset_name: assetName,
      target_ref: targetRef,
      report_file: selectedFile,
      scan_started_at: scanStartedAt,
    })
  }

  function handleFileList(files: FileList | null) {
    const file = files?.item(0) ?? null
    setSelectedFile(file)
    setAssetName("")
    setTargetRef("")
    setScanStartedAt("")
    importMutation.reset()
    if (file && selectedProjectId) {
      previewMutation.mutate({ project_id: selectedProjectId, report_file: file })
    } else {
      previewMutation.reset()
    }
  }

  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-normal">Import Scans</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {importsWorkspaceDescription()}
          </p>
        </div>
      </header>

      <div className="inline-flex rounded-md border bg-card p-1">
        <button
          aria-current="page"
          className="rounded-sm bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground"
          type="button"
        >
          Upload scans
        </button>
      </div>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-3">
            <div>
              <CardTitle className="text-base">Upload Report</CardTitle>
              <CardDescription>
                Bind the report to a project, optionally under a folder path.
              </CardDescription>
            </div>
            <SupportedReportsHelp />
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Project">
                <Select
                  disabled={projectsQuery.isPending || projects.length === 0}
                  onChange={(value) => {
                    setSelectedProjectId(value)
                    setFolderPath("")
                    setAssetName("")
                    setTargetRef("")
                    importMutation.reset()
                    if (selectedFile) {
                      previewMutation.mutate({ project_id: value, report_file: selectedFile })
                    } else {
                      previewMutation.reset()
                    }
                  }}
                  value={selectedProjectId}
                >
                  {projects.length === 0 ? (
                    <option value="">No projects available</option>
                  ) : (
                    projects.map((project) => (
                      <option key={project.id} value={project.id}>
                        {projectLabel(project)}
                      </option>
                    ))
                  )}
                </Select>
              </Field>

              <Field label="Folder">
                <Input
                  disabled={!selectedProjectId}
                  list="import-folder-path-options"
                  onChange={(event) => {
                    setFolderPath(event.target.value)
                    importMutation.reset()
                  }}
                  value={folderPath}
                />
                <datalist id="import-folder-path-options">
                  {folders.map((folder) => (
                    <option key={folder.id} value={folder.path}>
                      {assetLabel(folder)}
                    </option>
                  ))}
                </datalist>
              </Field>

              <Field label="Asset name">
                <Input
                  onChange={(event) => {
                    setAssetName(event.target.value)
                    importMutation.reset()
                  }}
                  value={assetName}
                />
              </Field>

              <Field label="Asset reference">
                <Input
                  onChange={(event) => {
                    setTargetRef(event.target.value)
                    importMutation.reset()
                  }}
                  value={targetRef}
                />
              </Field>

              <Field label="Tool">
                <Input
                  readOnly
                  value={toolFeedbackForReportFile(
                    selectedFile,
                    preview,
                    previewMutation.isPending,
                    previewMutation.isError,
                  )}
                />
              </Field>

              <Field label="Scan started at">
                <Input
                  onChange={(event) => {
                    setScanStartedAt(event.target.value)
                    importMutation.reset()
                  }}
                  type="datetime-local"
                  value={scanStartedAt}
                />
              </Field>
            </div>

            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
              <label
                className={cn(
                  "flex min-h-28 cursor-pointer flex-col items-center justify-center rounded-md border border-dashed bg-muted/30 px-4 py-5 text-center transition-colors",
                  isDraggingFile && "border-primary bg-accent/70",
                )}
                onDragEnter={(event) => {
                  event.preventDefault()
                  setIsDraggingFile(true)
                }}
                onDragLeave={(event) => {
                  event.preventDefault()
                  setIsDraggingFile(false)
                }}
                onDragOver={(event) => event.preventDefault()}
                onDrop={(event) => {
                  event.preventDefault()
                  setIsDraggingFile(false)
                  handleFileList(event.dataTransfer.files)
                }}
              >
                <FileUp className="mb-2 size-5 text-muted-foreground" aria-hidden="true" />
                <span className="text-sm font-medium">Drag or choose file</span>
                <span className="mt-1 max-w-full truncate text-xs text-muted-foreground">
                  {selectedFile ? selectedFile.name : "JSON report file"}
                </span>
                <input
                  className="sr-only"
                  key={fileInputKey}
                  onChange={(event) => handleFileList(event.target.files)}
                  type="file"
                />
              </label>

              <Button disabled={!canUpload} onClick={uploadReport} type="button">
                <Upload className="size-4" aria-hidden="true" />
                <span>{importMutation.isPending ? "Uploading..." : "Upload Report"}</span>
              </Button>
            </div>

            <StatusMessage
              error={importMutation.error}
              isAssetsError={assetsQuery.isError}
              isProjectsError={projectsQuery.isError}
              previewError={previewMutation.error}
              previewResult={preview}
              result={importMutation.data ?? null}
              selectedFileName={selectedFile?.name ?? null}
            />
          </CardContent>
        </Card>

        <Card className="xl:sticky xl:top-5">
          <CardHeader>
            <div>
              <CardTitle className="text-base">Folder Preview</CardTitle>
              <CardDescription>
                {selectedProject ? projectLabel(selectedProject) : "Select a project"}
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <SelectedFolderSummary
              folder={selectedFolder}
              folderPath={folderPath}
              project={selectedProject}
            />
            <AssetTree
              assets={assets}
              folderPath={folderPath}
              isError={assetsQuery.isError}
              isLoading={assetsQuery.isPending && selectedProjectId.length > 0}
              pendingAsset={pendingAsset}
              pendingFolders={pendingFolders}
            />
          </CardContent>
        </Card>
      </section>
    </div>
  )
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
      className="flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      value={value}
    >
      {children}
    </select>
  )
}

function SupportedReportsHelp() {
  return (
    <details className="group relative shrink-0">
      <summary
        aria-label="Supported report formats"
        className="flex size-9 cursor-pointer list-none items-center justify-center rounded-md border bg-background text-muted-foreground shadow-xs transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden"
      >
        <Info className="size-4" aria-hidden="true" />
      </summary>
      <div className="absolute right-0 z-20 mt-2 hidden w-72 rounded-md border bg-popover p-3 text-sm text-popover-foreground shadow-md group-hover:block group-open:block">
        <p className="font-medium">Supported report formats</p>
        <ul className="mt-2 list-disc space-y-1 pl-4 text-muted-foreground">
          {supportedImportReportFormats().map((format) => (
            <li key={format.label}>
              {format.label}: <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">{format.command}</code>
            </li>
          ))}
        </ul>
      </div>
    </details>
  )
}

function SelectedFolderSummary({
  folder,
  folderPath,
  project,
}: {
  folder: Asset | null
  folderPath: string
  project: Project | null
}) {
  if (!project) {
    return <p className="text-sm text-muted-foreground">No project selected.</p>
  }

  const normalizedFolderPath = normalizeImportFolderPath(folderPath)
  if (!normalizedFolderPath) {
    return (
      <div className="rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground">
        Imports without a folder path will be placed at the project root.
      </div>
    )
  }

  if (!folder) {
    return (
      <div className="rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground">
        This folder path will be created during import.
      </div>
    )
  }

  return (
    <dl className="grid gap-3 rounded-md border bg-muted/30 p-3 text-sm">
      <div>
        <dt className="text-xs text-muted-foreground">Folder</dt>
        <dd className="mt-1 font-medium">{folder.name}</dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Path</dt>
        <dd className="mt-1 break-words">{folder.path}</dd>
      </div>
    </dl>
  )
}

function AssetTree({
  assets,
  folderPath,
  isError,
  isLoading,
  pendingAsset,
  pendingFolders,
}: {
  assets: Asset[]
  folderPath: string
  isError: boolean
  isLoading: boolean
  pendingAsset: Asset | null
  pendingFolders: Asset[]
}) {
  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading assets...</p>
  }

  if (isError) {
    return <p className="text-sm text-destructive">Unable to load project assets.</p>
  }

  if (assets.length === 0 && pendingFolders.length === 0) {
    return <p className="text-sm text-muted-foreground">No assets available for this project.</p>
  }

  const rows = flattenAssets([
    ...assets,
    ...pendingFolders,
    ...(pendingAsset ? [pendingAsset] : []),
  ])
  const selectedFolderPath = normalizeImportFolderPath(folderPath)
  return (
    <div className="space-y-2">
      <h2 className="text-xs font-semibold uppercase text-muted-foreground">Project assets</h2>
      <ul className="space-y-1">
        {rows.map(({ asset, depth }) => (
          <li
            className={cn(
              "rounded-md border px-2 py-1.5 text-sm",
              selectedFolderPath === asset.path ? "border-primary bg-accent" : "bg-background",
              (asset.id === pendingImportAssetId ||
                asset.id.startsWith(pendingImportFolderIdPrefix)) &&
                "border-primary border-dashed bg-primary/5",
            )}
            key={asset.id}
            style={{ marginLeft: `${Math.min(depth, 5) * 0.75}rem` }}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="min-w-0 truncate font-medium">{asset.name}</span>
              <Badge variant={asset.type === scanTargetType ? "default" : "outline"}>
                {assetBadgeLabel(asset)}
              </Badge>
            </div>
            <p className="mt-1 truncate text-xs text-muted-foreground">{asset.path}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

function StatusMessage({
  error,
  isAssetsError,
  isProjectsError,
  previewError,
  previewResult,
  result,
  selectedFileName,
}: {
  error: Error | null
  isAssetsError: boolean
  isProjectsError: boolean
  previewError: Error | null
  previewResult: TrivyImportPreviewResponse | null
  result: ImportTrivyReportResponse | null
  selectedFileName: string | null
}) {
  if (isProjectsError) {
    return <Callout tone="error" title="Unable to load projects" />
  }

  if (isAssetsError) {
    return <Callout tone="error" title="Unable to load project assets" />
  }

  if (error) {
    return <Callout tone="error" title="Import failed" body={safeErrorMessage(error)} />
  }

  if (previewError) {
    return (
      <Callout tone="error" title="Report preview failed" body={safeErrorMessage(previewError)} />
    )
  }

  if (result) {
    const message = importCompleteMessage(result, selectedFileName)
    return (
      <Callout
        tone="success"
        title={message.title}
        body={message.body}
      />
    )
  }

  if (previewResult) {
    return (
      <Callout
        tone="success"
        title="Report parsed"
        body={`${previewResult.finding_count} findings across ${previewResult.group_count} groups detected.`}
      />
    )
  }

  return null
}

function Callout({
  body,
  title,
  tone,
}: {
  body?: string
  title: string
  tone: "error" | "success"
}) {
  const Icon = tone === "error" ? AlertCircle : CheckCircle2
  return (
    <div
      className={cn(
        "flex gap-2 rounded-md border px-3 py-2 text-sm",
        tone === "error"
          ? "border-destructive/40 text-destructive"
          : "border-primary/30 text-foreground",
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div>
        <p className="font-medium">{title}</p>
        {body ? <p className="mt-1 text-muted-foreground">{body}</p> : null}
      </div>
    </div>
  )
}

function flattenAssets(assets: Asset[]): Array<{ asset: Asset; depth: number }> {
  const byParent = new Map<string, Asset[]>()
  const assetIds = new Set(assets.map((asset) => asset.id))

  for (const asset of assets) {
    const parentKey = asset.parent_id && assetIds.has(asset.parent_id) ? asset.parent_id : "root"
    const siblings = byParent.get(parentKey) ?? []
    siblings.push(asset)
    byParent.set(parentKey, siblings)
  }

  for (const siblings of byParent.values()) {
    siblings.sort(compareAssets)
  }

  const rows: Array<{ asset: Asset; depth: number }> = []
  const visited = new Set<string>()

  function visit(parentId: string, depth: number) {
    for (const asset of byParent.get(parentId) ?? []) {
      if (visited.has(asset.id)) {
        continue
      }
      visited.add(asset.id)
      rows.push({ asset, depth })
      visit(asset.id, depth + 1)
    }
  }

  visit("root", 0)
  return rows
}

function compareAssets(left: Asset, right: Asset): number {
  return left.sort_order - right.sort_order || left.name.localeCompare(right.name)
}

export function folderOptionsForImport(assets: Asset[]): Asset[] {
  return assets.filter((asset) => asset.type === folderType).sort(compareAssets)
}

export function normalizeImportFolderPath(folderPath: string): string {
  return folderPath
    .split("/")
    .map((segment) => segment.trim())
    .join("/")
    .trim()
}

export function pendingImportFolders(existingFolders: Asset[], folderPath: string): Asset[] {
  const normalizedFolderPath = normalizeImportFolderPath(folderPath)
  if (!normalizedFolderPath) {
    return []
  }

  const existingByPath = new Map(existingFolders.map((folder) => [folder.path, folder]))
  const pendingFolders: Asset[] = []
  let parentId: string | null = null
  let currentPath = ""

  for (const segment of normalizedFolderPath.split("/")) {
    currentPath = currentPath ? `${currentPath}/${segment}` : segment
    const existingFolder = existingByPath.get(currentPath)
    if (existingFolder) {
      parentId = existingFolder.id
      continue
    }

    const pendingFolder: Asset = {
      id: pendingImportFolderId(currentPath),
      parent_id: parentId,
      path: currentPath,
      type: folderType,
      name: segment,
      target_ref: null,
      scan_label: null,
      sla_tracking_enabled: null,
      sla_reporting_enabled: null,
      grace_period_enabled: null,
      grace_period_percent: null,
      sort_order: Number.MAX_SAFE_INTEGER - pendingFolders.length,
    }
    pendingFolders.push(pendingFolder)
    parentId = pendingFolder.id
  }

  return pendingFolders
}

export function folderForImportPath(folders: Asset[], folderPath: string): Asset | null {
  const normalizedFolderPath = normalizeImportFolderPath(folderPath)
  if (!normalizedFolderPath) {
    return null
  }
  return (
    folders.find((folder) => folder.type === folderType && folder.path === normalizedFolderPath) ??
    pendingImportFolders(folders, normalizedFolderPath).at(-1) ??
    null
  )
}

export function supportedImportReportFormats(): Array<{ command: string; label: string }> {
  return [{ command: "trivy image --format json", label: "Trivy" }]
}

export function importsWorkspaceDescription(): string {
  return "Upload supported scanner reports against existing projects and assets."
}

export function importCompleteMessage(
  result: ImportTrivyReportResponse,
  fileName: string | null,
): { body: string; title: string } {
  const importedThing = fileName?.trim() ? fileName.trim() : "report"
  return {
    title: `Import of ${importedThing} complete, with ID ${result.import_attempt_id}.`,
    body: `${result.finding_count} findings across ${result.group_count} groups.`,
  }
}

function filterFoldersForImport(folders: Asset[], search: string): Asset[] {
  const normalizedSearch = search.trim().toLocaleLowerCase()
  if (!normalizedSearch) {
    return folders
  }
  return folders.filter((folder) =>
    `${folder.name} ${folder.path}`.toLocaleLowerCase().includes(normalizedSearch),
  )
}

export function toolFeedbackForReportFile(
  file: File | null,
  preview: TrivyImportPreviewResponse | null = null,
  isParsing = false,
  isError = false,
): string {
  if (!file) {
    return ""
  }
  if (isParsing) {
    return "Parsing report..."
  }
  if (preview) {
    return preview.tool_label
  }
  if (isError) {
    return ""
  }
  return ""
}

export function datetimeLocalFromIso(value: string | null | undefined): string {
  if (!value) {
    return ""
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ""
  }
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, "0")
  const day = String(date.getDate()).padStart(2, "0")
  const hours = String(date.getHours()).padStart(2, "0")
  const minutes = String(date.getMinutes()).padStart(2, "0")
  return `${year}-${month}-${day}T${hours}:${minutes}`
}

export function importFormDefaultsFromPreview(
  current: {
    folderPath: string
    assetName: string
    targetRef: string
    scanStartedAt: string
  },
  preview: TrivyImportPreviewResponse,
): {
  folderPath: string
  assetName: string
  targetRef: string
  scanStartedAt: string
} {
  return {
    folderPath: current.folderPath || preview.detected_project_name || "",
    assetName: current.assetName || preview.detected_asset_name || "",
    targetRef: current.targetRef || preview.detected_target_ref || "",
    scanStartedAt: current.scanStartedAt || datetimeLocalFromIso(preview.scan_started_at),
  }
}

export function canUploadReport({
  file,
  hasProject,
  hasSuccessfulPreview,
  isUploading,
}: {
  file: File | null
  folderPath: string
  hasProject: boolean
  hasSuccessfulPreview: boolean
  isUploading: boolean
}): boolean {
  return (
    hasProject &&
    file !== null &&
    hasSuccessfulPreview &&
    !isUploading
  )
}

export function pendingImportAsset(
  selectedFolder: Asset | null,
  assetName: string,
  targetRef: string,
  preview: TrivyImportPreviewResponse | null,
): Asset | null {
  if (!preview) {
    return null
  }
  const resolvedName = assetName.trim() || preview.detected_asset_name || "Detected asset"
  const resolvedTargetRef = targetRef.trim() || preview.detected_target_ref || null
  const parentPath = selectedFolder?.path ?? ""
  return {
    id: pendingImportAssetId,
    parent_id: selectedFolder?.id ?? null,
    path: parentPath ? `${parentPath}/${resolvedName}` : resolvedName,
    type: scanTargetType,
    name: resolvedName,
    target_ref: resolvedTargetRef,
    scan_label: importPreviewScanLabel(preview),
    sla_tracking_enabled: null,
    sla_reporting_enabled: null,
    grace_period_enabled: null,
    grace_period_percent: null,
    sort_order: Number.MAX_SAFE_INTEGER,
  }
}


function pendingImportFolderId(path: string): string {
  return `${pendingImportFolderIdPrefix}${path}`
}

function projectLabel(project: Project): string {
  return project.slug && project.slug !== project.name
    ? `${project.name} / ${project.slug}`
    : project.name
}

function assetLabel(asset: Asset): string {
  return asset.path && asset.path !== asset.name ? `${asset.name} / ${asset.path}` : asset.name
}

function assetTypeLabel(type: string): string {
  if (type === scanTargetType) {
    return "Asset"
  }
  return type
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toLocaleUpperCase())
}

function assetBadgeLabel(asset: Asset): string {
  return asset.scan_label ?? assetTypeLabel(asset.type)
}

function importPreviewScanLabel(preview: TrivyImportPreviewResponse): string {
  if (preview.scanner === "trivy" && preview.report_kind === "trivy-image-json") {
    return "Trivy Image Scan"
  }
  return preview.tool_label
}

function safeErrorMessage(error: Error): string {
  if (error instanceof ApiError) {
    return error.message
  }
  return "The backend API did not accept the report."
}
