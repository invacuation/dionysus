import {
  AlertCircle,
  Box,
  CheckCircle2,
  Folder,
  FolderTree,
  PackageSearch,
  Plus,
  Save,
  Search,
  Trash2,
} from "lucide-react"
import {
  useEffect,
  useMemo,
  useState,
  type DragEvent,
  type FormEvent,
  type ReactNode,
} from "react"
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
  createFolder,
  createProject,
  deleteAsset,
  deleteProject,
  listProjectAssets,
  listProjects,
  updateAsset,
  updateProject,
  type Asset,
  type Project,
  type UpdateAssetParams,
  type UpdateProjectParams,
} from "@/lib/api"
import { treeIndentPadding } from "@/lib/tree-layout"
import { cn } from "@/lib/utils"

const scanTargetType = "scan_target"
const folderType = "folder"
const selectClassName =
  "flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-sm shadow-xs outline-none transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"

type OverrideSelectValue = "inherit" | "enabled" | "disabled"
type SlaOverrideKind = "tracking" | "reporting"

type AssetTreeRow =
  | {
      kind: "group"
      id: string
      name: string
      path: string
      depth: number
    }
  | {
      kind: "asset"
      asset: Asset
      depth: number
    }

export function InventoryPage() {
  const queryClient = useQueryClient()
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [selectedAssetId, setSelectedAssetId] = useState("")
  const [projectSearch, setProjectSearch] = useState("")
  const [assetSearch, setAssetSearch] = useState("")
  const [isCreateProjectOpen, setIsCreateProjectOpen] = useState(false)
  const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false)

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
      setSelectedAssetId("")
    }
  }, [projects, selectedProjectId])

  const assetsQuery = useQuery({
    queryKey: ["projects", selectedProjectId, "assets"],
    queryFn: () => listProjectAssets(selectedProjectId),
    enabled: selectedProjectId.length > 0,
  })

  const assets = assetsQuery.data?.assets ?? []
  const filteredProjects = useMemo(
    () => filterProjects(projects, projectSearch),
    [projects, projectSearch],
  )
  const filteredAssets = useMemo(() => filterAssetTree(assets, assetSearch), [assets, assetSearch])
  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null
  const selectedAsset = assets.find((asset) => asset.id === selectedAssetId) ?? null
  const canOpenCreateFolder = canCreateFolderForSelection(selectedProjectId, selectedAsset)

  useEffect(() => {
    if (assets.length === 0) {
      setSelectedAssetId("")
      return
    }
    if (!assets.some((asset) => asset.id === selectedAssetId)) {
      setSelectedAssetId(assets[0].id)
    }
  }, [assets, selectedAssetId])

  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
          <div>
            <h1 className="text-2xl font-semibold tracking-normal">Asset Inventory</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              Browse and update project assets, folders, and SLA settings.
            </p>
          </div>
        </div>
      </header>

      <section className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)_24rem]">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between gap-3">
              <div>
                <CardTitle className="text-base">Projects</CardTitle>
                <CardDescription>Select a project to inspect its asset tree.</CardDescription>
              </div>
              {filteredProjects.length > 0 ? (
                <Badge variant="outline">{projectCountLabel(filteredProjects.length)}</Badge>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-2">
              <SearchInput
                label="Search projects"
                onChange={setProjectSearch}
                placeholder="Search projects"
                value={projectSearch}
              />
              <Button
                aria-expanded={isCreateProjectOpen}
                aria-label="Add project"
                onClick={() => setIsCreateProjectOpen((isOpen) => !isOpen)}
                size="icon"
                title="Add project"
                type="button"
                variant={isCreateProjectOpen ? "secondary" : "outline"}
              >
                <Plus className="size-4" aria-hidden="true" />
              </Button>
            </div>
            {isCreateProjectOpen ? (
              <CreateProjectForm
                onCreated={async (project) => {
                  setIsCreateProjectOpen(false)
                  setSelectedAssetId("")
                  await queryClient.invalidateQueries({ queryKey: ["projects"] })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                  setSelectedProjectId(project.id)
                }}
              />
            ) : null}
            <ProjectList
              isError={projectsQuery.isError}
              isLoading={projectsQuery.isPending}
              onSelect={(projectId) => {
                setSelectedProjectId(projectId)
                setSelectedAssetId("")
              }}
              projects={filteredProjects}
              selectedProjectId={selectedProjectId}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-start justify-between gap-3">
              <div>
                <CardTitle className="text-base">Asset Tree</CardTitle>
                <CardDescription>
                  {selectedProject ? projectLabel(selectedProject) : "Select a project"}
                </CardDescription>
              </div>
              {assets.length > 0 ? <Badge variant="outline">{assets.length} assets</Badge> : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-2">
              <SearchInput
                label="Search assets"
                onChange={setAssetSearch}
                placeholder="Search assets"
                value={assetSearch}
              />
              <Button
                aria-expanded={isCreateFolderOpen}
                aria-label="Add folder"
                disabled={!canOpenCreateFolder}
                onClick={() => setIsCreateFolderOpen((isOpen) => !isOpen)}
                size="icon"
                title={canOpenCreateFolder ? "Add folder" : "Select a project folder first"}
                type="button"
                variant={isCreateFolderOpen ? "secondary" : "outline"}
              >
                <Plus className="size-4" aria-hidden="true" />
              </Button>
            </div>
            {isCreateFolderOpen ? (
              <CreateFolderForm
                assets={assets}
                onCreated={async (asset) => {
                  setIsCreateFolderOpen(false)
                  await queryClient.invalidateQueries({
                    queryKey: ["projects", selectedProjectId, "assets"],
                  })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                  setSelectedAssetId(asset.id)
                }}
                selectedAsset={selectedAsset}
                selectedProjectId={selectedProjectId}
              />
            ) : null}
            <AssetTree
              assets={assets}
              isError={assetsQuery.isError}
              isLoading={assetsQuery.isPending && selectedProjectId.length > 0}
              onSelect={setSelectedAssetId}
              selectedAssetId={selectedAssetId}
              selectedProjectId={selectedProjectId}
              visibleAssets={filteredAssets}
            />
          </CardContent>
        </Card>

        <div className="space-y-4 xl:sticky xl:top-5 xl:self-start">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Project Settings</CardTitle>
              <CardDescription>
                {selectedProject ? selectedProject.slug : "No project selected"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ProjectSettingsSummary
                onSaved={async () => {
                  await queryClient.invalidateQueries({ queryKey: ["projects"] })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                }}
                onDeleted={async () => {
                  setSelectedProjectId("")
                  setSelectedAssetId("")
                  setAssetSearch("")
                  await queryClient.invalidateQueries({ queryKey: ["projects"] })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                }}
                project={selectedProject}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Asset Details</CardTitle>
            </CardHeader>
            <CardContent>
              <AssetDetail
                asset={selectedAsset}
                assets={assets}
                onSaved={async (asset) => {
                  await queryClient.invalidateQueries({
                    queryKey: ["projects", selectedProjectId, "assets"],
                  })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                  setSelectedAssetId(asset.id)
                }}
                onDeleted={async () => {
                  setSelectedAssetId("")
                  await queryClient.invalidateQueries({
                    queryKey: ["projects", selectedProjectId, "assets"],
                  })
                  await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
                }}
                project={selectedProject}
                selectedProjectId={selectedProjectId}
              />
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  )
}

function CreateProjectForm({ onCreated }: { onCreated: (project: Project) => Promise<void> }) {
  const [slug, setSlug] = useState("")
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")

  const createProjectMutation = useMutation({
    mutationFn: createProject,
    onSuccess: async (project) => {
      setSlug("")
      setName("")
      setDescription("")
      await onCreated(project)
    },
  })

  const canSubmit = slug.trim().length > 0 && name.trim().length > 0

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canSubmit || createProjectMutation.isPending) {
      return
    }
    createProjectMutation.mutate({
      slug: slug.trim(),
      name: name.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
    })
  }

  return (
    <form className="space-y-3 border-t pt-4" onSubmit={handleSubmit}>
      <div>
        <h2 className="text-sm font-medium">Create Project</h2>
        <p className="text-xs text-muted-foreground">Add a project and select it.</p>
      </div>
      <Input
        aria-label="Project slug"
        onChange={(event) => setSlug(event.target.value)}
        placeholder="slug"
        value={slug}
      />
      <Input
        aria-label="Project name"
        onChange={(event) => setName(event.target.value)}
        placeholder="Name"
        value={name}
      />
      <Textarea
        aria-label="Project description"
        className="min-h-16"
        onChange={(event) => setDescription(event.target.value)}
        placeholder="Description (optional)"
        value={description}
      />
      {createProjectMutation.isError ? (
        <StateMessage tone="error">{errorMessage(createProjectMutation.error)}</StateMessage>
      ) : null}
      <Button disabled={!canSubmit || createProjectMutation.isPending} size="sm" type="submit">
        Create project
      </Button>
    </form>
  )
}

function CreateFolderForm({
  assets,
  onCreated,
  selectedAsset,
  selectedProjectId,
}: {
  assets: Asset[]
  onCreated: (asset: Asset) => Promise<void>
  selectedAsset: Asset | null
  selectedProjectId: string
}) {
  const [folderPath, setFolderPath] = useState("")
  const placeholder = createFolderPathPlaceholder(selectedAsset, assets)
  const canUseFolderForm = canCreateFolderForSelection(selectedProjectId, selectedAsset)

  const createFolderMutation = useMutation({
    mutationFn: (path: string) => createFolder(selectedProjectId, { path }),
    onSuccess: async (asset) => {
      setFolderPath("")
      await onCreated(asset)
    },
  })

  const canCreateFolder = canUseFolderForm && folderPath.trim().length > 0

  function handleCreateFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canCreateFolder || createFolderMutation.isPending) {
      return
    }
    createFolderMutation.mutate(folderPath.trim())
  }

  return (
    <div className={cn("border-t pt-4", !canUseFolderForm && "opacity-60")}>
      <form className="space-y-3" onSubmit={handleCreateFolder}>
        <div>
          <h2 className="text-sm font-medium">Create Folder</h2>
          <p className="text-xs text-muted-foreground">Add a new folder to this project.</p>
        </div>
        <Input
          aria-label="Folder path"
          disabled={!canUseFolderForm}
          onChange={(event) => setFolderPath(event.target.value)}
          placeholder={placeholder}
          value={folderPath}
        />
        {createFolderMutation.isError ? (
          <StateMessage tone="error">{errorMessage(createFolderMutation.error)}</StateMessage>
        ) : null}
        <Button
          disabled={!canCreateFolder || createFolderMutation.isPending}
          size="sm"
          type="submit"
          variant="outline"
        >
          Create folder
        </Button>
      </form>
    </div>
  )
}

function SearchInput({
  label,
  onChange,
  placeholder,
  value,
}: {
  label: string
  onChange: (value: string) => void
  placeholder: string
  value: string
}) {
  return (
    <label className="relative block">
      <span className="sr-only">{label}</span>
      <Search
        className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden="true"
      />
      <Input
        aria-label={label}
        className="pl-9"
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        value={value}
      />
    </label>
  )
}

function ProjectList({
  isError,
  isLoading,
  onSelect,
  projects,
  selectedProjectId,
}: {
  isError: boolean
  isLoading: boolean
  onSelect: (projectId: string) => void
  projects: Project[]
  selectedProjectId: string
}) {
  if (isLoading) {
    return <StateMessage>Loading projects...</StateMessage>
  }

  if (isError) {
    return <StateMessage tone="error">Unable to load projects.</StateMessage>
  }

  if (projects.length === 0) {
    return <StateMessage>No projects available yet.</StateMessage>
  }

  return (
    <div className="space-y-1">
      {projects.map((project) => (
        <button
          className={cn(
            "grid w-full gap-1 rounded-md border px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
            selectedProjectId === project.id
              ? "border-primary bg-accent text-accent-foreground"
              : "bg-background",
          )}
          key={project.id}
          onClick={() => onSelect(project.id)}
          type="button"
        >
          <span className="truncate font-medium">{project.name}</span>
          <span className="truncate text-xs text-muted-foreground">{project.slug}</span>
        </button>
      ))}
    </div>
  )
}

function AssetTree({
  assets,
  isError,
  isLoading,
  onSelect,
  selectedAssetId,
  selectedProjectId,
  visibleAssets,
}: {
  assets: Asset[]
  isError: boolean
  isLoading: boolean
  onSelect: (assetId: string) => void
  selectedAssetId: string
  selectedProjectId: string
  visibleAssets: Asset[]
}) {
  const queryClient = useQueryClient()
  const [draggedAssetId, setDraggedAssetId] = useState<string | null>(null)
  const [activeDropParentId, setActiveDropParentId] = useState<string | null | undefined>()
  const [moveError, setMoveError] = useState("")
  const rows = useMemo(() => flattenAssets(visibleAssets), [visibleAssets])
  const draggedAsset = draggedAssetId
    ? assets.find((candidate) => candidate.id === draggedAssetId) ?? null
    : null
  const moveAssetMutation = useMutation({
    mutationFn: ({ asset, parentId }: { asset: Asset; parentId: string | null }) =>
      updateAsset(selectedProjectId, asset.id, assetMovePayload(asset, parentId)),
    onSuccess: async (asset) => {
      setMoveError("")
      await queryClient.invalidateQueries({
        queryKey: ["projects", selectedProjectId, "assets"],
      })
      await queryClient.invalidateQueries({ queryKey: ["audit-log"] })
      onSelect(asset.id)
    },
    onError: (error) => {
      setMoveError(errorMessage(error))
    },
    onSettled: () => {
      setDraggedAssetId(null)
      setActiveDropParentId(undefined)
    },
  })

  function handleDragStart(event: DragEvent<HTMLElement>, asset: Asset) {
    setMoveError("")
    setDraggedAssetId(asset.id)
    event.dataTransfer.effectAllowed = "move"
    event.dataTransfer.setData("text/plain", asset.id)
  }

  function handleDragEnd() {
    if (!moveAssetMutation.isPending) {
      setDraggedAssetId(null)
      setActiveDropParentId(undefined)
    }
  }

  function handleDrop(event: DragEvent<HTMLElement>, parentId: string | null) {
    event.preventDefault()
    const draggedId = event.dataTransfer.getData("text/plain") || draggedAssetId
    const asset = assets.find((candidate) => candidate.id === draggedId)
    if (
      !asset ||
      !selectedProjectId ||
      !canMoveAssetToParent(asset, parentId, assets) ||
      moveAssetMutation.isPending
    ) {
      setActiveDropParentId(undefined)
      return
    }
    if (asset.parent_id === parentId) {
      onSelect(asset.id)
      setDraggedAssetId(null)
      setActiveDropParentId(undefined)
      return
    }
    moveAssetMutation.mutate({ asset, parentId })
  }

  function handleDragOver(event: DragEvent<HTMLElement>, parentId: string | null) {
    if (draggedAsset && canMoveAssetToParent(draggedAsset, parentId, assets)) {
      event.preventDefault()
      event.dataTransfer.dropEffect = "move"
      setActiveDropParentId(parentId)
    }
  }

  function handleDragLeave(parentId: string | null) {
    setActiveDropParentId((current) => (current === parentId ? undefined : current))
  }

  if (!selectedProjectId) {
    return <StateMessage>Select a project to load its inventory.</StateMessage>
  }

  if (isLoading) {
    return <StateMessage>Loading project assets...</StateMessage>
  }

  if (isError) {
    return <StateMessage tone="error">Unable to load project assets.</StateMessage>
  }

  if (assets.length === 0) {
    return <StateMessage>This project does not have inventory assets yet.</StateMessage>
  }

  if (visibleAssets.length === 0) {
    return <StateMessage>No assets match this search.</StateMessage>
  }

  return (
    <div className="space-y-2">
      <button
        className={cn(
          "flex min-h-10 w-full items-center gap-2 rounded-md border border-dashed px-3 py-2 text-left text-sm text-muted-foreground transition-colors",
          activeDropParentId === null && "border-primary bg-accent text-accent-foreground",
        )}
        onDragLeave={() => handleDragLeave(null)}
        onDragOver={(event) => handleDragOver(event, null)}
        onDrop={(event) => handleDrop(event, null)}
        type="button"
      >
        <FolderTree className="size-4 shrink-0" aria-hidden="true" />
        <span className="truncate">Root</span>
      </button>
      {moveError ? <StateMessage tone="error">{moveError}</StateMessage> : null}
      <div className="overflow-hidden rounded-md border">
      <ul className="divide-y">
        {rows.map((row) =>
          row.kind === "group" ? (
            <li
              className="flex min-h-10 items-center gap-2 bg-muted/30 px-3 py-2 text-sm text-muted-foreground"
              key={row.id}
              style={{ paddingLeft: treeIndentPadding(row.depth) }}
            >
              <FolderTree className="size-4 shrink-0" aria-hidden="true" />
              <span className="min-w-0 truncate font-medium">{row.name}</span>
            </li>
          ) : (
            <AssetTreeNode
              asset={row.asset}
              depth={row.depth}
              draggedAsset={draggedAsset}
              isSelected={selectedAssetId === row.asset.id}
              key={row.asset.id}
              onDragEnd={handleDragEnd}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDragStart={handleDragStart}
              onDrop={handleDrop}
              onSelect={onSelect}
              activeDropParentId={activeDropParentId}
              assets={assets}
            />
          ),
        )}
      </ul>
      </div>
    </div>
  )
}

function AssetTreeNode({
  activeDropParentId,
  asset,
  assets,
  depth,
  draggedAsset,
  isSelected,
  onDragEnd,
  onDragLeave,
  onDragOver,
  onDragStart,
  onDrop,
  onSelect,
}: {
  activeDropParentId: string | null | undefined
  asset: Asset
  assets: Asset[]
  depth: number
  draggedAsset: Asset | null
  isSelected: boolean
  onDragEnd: () => void
  onDragLeave: (parentId: string | null) => void
  onDragOver: (event: DragEvent<HTMLElement>, parentId: string | null) => void
  onDragStart: (event: DragEvent<HTMLElement>, asset: Asset) => void
  onDrop: (event: DragEvent<HTMLElement>, parentId: string | null) => void
  onSelect: (assetId: string) => void
}) {
  const Icon = asset.type === folderType ? Folder : asset.type === scanTargetType ? PackageSearch : Box
  const acceptsDrop =
    asset.type === folderType && draggedAsset
      ? canMoveAssetToParent(draggedAsset, asset.id, assets)
      : false

  return (
    <li>
      <button
        aria-current={isSelected ? "true" : undefined}
        className={cn(
          "grid min-h-12 w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-accent",
          isSelected && "bg-accent text-accent-foreground",
          activeDropParentId === asset.id && acceptsDrop && "bg-accent text-accent-foreground",
          draggedAsset?.id === asset.id && "opacity-60",
        )}
        draggable
        onDragEnd={onDragEnd}
        onDragLeave={() => {
          if (asset.type === folderType) {
            onDragLeave(asset.id)
          }
        }}
        onDragOver={(event) => {
          if (asset.type === folderType) {
            onDragOver(event, asset.id)
          }
        }}
        onDragStart={(event) => onDragStart(event, asset)}
        onDrop={(event) => {
          if (asset.type === folderType) {
            onDrop(event, asset.id)
          }
        }}
        onClick={() => onSelect(asset.id)}
        style={{ paddingLeft: treeIndentPadding(depth) }}
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

function ProjectSettingsSummary({
  onDeleted,
  onSaved,
  project,
}: {
  onDeleted: () => Promise<void>
  onSaved: () => Promise<void>
  project: Project | null
}) {
  const [gracePercent, setGracePercent] = useState("")

  useEffect(() => {
    setGracePercent(project ? String(project.grace_period_percent) : "")
  }, [project?.id, project?.grace_period_percent])

  const updateProjectMutation = useMutation({
    mutationFn: (payload: UpdateProjectParams) => {
      if (!project) {
        throw new Error("No project selected.")
      }
      return updateProject(project.id, payload)
    },
    onSuccess: onSaved,
  })
  const deleteProjectMutation = useMutation({
    mutationFn: () => {
      if (!project) {
        throw new Error("No project selected.")
      }
      return deleteProject(project.id)
    },
    onSuccess: onDeleted,
  })

  function handleDeleteProject() {
    if (
      !project ||
      deleteProjectMutation.isPending ||
      !window.confirm(projectDeleteWarning(project))
    ) {
      return
    }
    deleteProjectMutation.mutate()
  }

  if (!project) {
    return <StateMessage>No project selected.</StateMessage>
  }

  return (
    <div className="space-y-4">
      {project.description ? (
        <p className="text-sm text-muted-foreground">{project.description}</p>
      ) : null}
      <dl className="grid gap-3 text-sm">
        <DetailRow label="SLA tracking">
          <StatusPill enabled={project.sla_tracking_enabled} />
        </DetailRow>
        <DetailRow label="SLA reporting">
          <StatusPill enabled={project.sla_reporting_enabled} />
        </DetailRow>
        <DetailRow label="Peer review">
          <StatusPill enabled={project.require_peer_review_for_status_changes} />
        </DetailRow>
        <DetailRow label="Grace period">
          <span>{project.grace_period_enabled ? "Enabled" : "Disabled"}</span>
        </DetailRow>
        <DetailRow label="Grace percent">
          <span className="inline-block min-w-max whitespace-nowrap">
            {project.grace_period_percent}%
          </span>
        </DetailRow>
      </dl>
      {updateProjectMutation.isError ? (
        <StateMessage tone="error">{errorMessage(updateProjectMutation.error)}</StateMessage>
      ) : null}
      {deleteProjectMutation.isError ? (
        <StateMessage tone="error">{errorMessage(deleteProjectMutation.error)}</StateMessage>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          disabled={updateProjectMutation.isPending}
          onClick={() =>
            updateProjectMutation.mutate({
              require_peer_review_for_status_changes:
                !project.require_peer_review_for_status_changes,
            })
          }
          size="sm"
          type="button"
          variant="outline"
        >
          {updateProjectMutation.isPending
            ? "Saving..."
            : project.require_peer_review_for_status_changes
              ? "Disable peer review"
              : "Require peer review"}
        </Button>
        <Button
          disabled={deleteProjectMutation.isPending}
          onClick={handleDeleteProject}
          size="sm"
          type="button"
          variant="outline"
        >
          <Trash2 className="size-4" aria-hidden="true" />
          Delete project
        </Button>
      </div>
      <form
        className="space-y-3 border-t pt-4"
        onSubmit={(event) => {
          event.preventDefault()
          const normalizedGracePercent = normalizeGracePercent(
            gracePercent,
            project.grace_period_percent,
          )
          updateProjectMutation.mutate({
            grace_period_enabled: project.grace_period_enabled,
            grace_period_percent: normalizedGracePercent,
          })
        }}
      >
        <div>
          <h3 className="text-sm font-medium">Grace period</h3>
          <p className="text-xs text-muted-foreground">
            Set the secondary SLA percentage for this project.
          </p>
        </div>
        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
          <Input
            aria-label="Grace percent"
            inputMode="numeric"
            onChange={(event) => setGracePercent(event.target.value)}
            value={gracePercent}
          />
          <Button
            disabled={updateProjectMutation.isPending}
            onClick={() =>
              updateProjectMutation.mutate({
                grace_period_enabled: !project.grace_period_enabled,
              })
            }
            type="button"
            variant="outline"
          >
            {project.grace_period_enabled ? "Disable grace period" : "Enable grace period"}
          </Button>
          <Button disabled={updateProjectMutation.isPending} type="submit" variant="outline">
            Save grace
          </Button>
        </div>
      </form>
    </div>
  )
}

function AssetDetail({
  asset,
  assets,
  onDeleted,
  onSaved,
  project,
  selectedProjectId,
}: {
  asset: Asset | null
  assets: Asset[]
  onDeleted: () => Promise<void>
  onSaved: (asset: Asset) => Promise<void>
  project: Project | null
  selectedProjectId: string
}) {
  const [name, setName] = useState("")
  const [slaTracking, setSlaTracking] = useState<OverrideSelectValue>("inherit")
  const [slaReporting, setSlaReporting] = useState<OverrideSelectValue>("inherit")

  useEffect(() => {
    setName(asset?.name ?? "")
    setSlaTracking(overrideToSelectValue(asset?.sla_tracking_enabled ?? null))
    setSlaReporting(overrideToSelectValue(asset?.sla_reporting_enabled ?? null))
  }, [asset])

  const updateAssetMutation = useMutation({
    mutationFn: () => {
      if (!asset) {
        throw new Error("No asset selected.")
      }
      return updateAsset(selectedProjectId, asset.id, {
        name: name.trim(),
        sla_tracking_enabled: selectValueToOverride(slaTracking),
        sla_reporting_enabled: selectValueToOverride(slaReporting),
      })
    },
    onSuccess: onSaved,
  })
  const deleteAssetMutation = useMutation({
    mutationFn: () => {
      if (!asset) {
        throw new Error("No asset selected.")
      }
      return deleteAsset(selectedProjectId, asset.id)
    },
    onSuccess: onDeleted,
  })

  const canSave =
    Boolean(asset) &&
    selectedProjectId.length > 0 &&
    name.trim().length > 0 &&
    !updateAssetMutation.isPending
  const canDelete = Boolean(asset) && selectedProjectId.length > 0 && !deleteAssetMutation.isPending

  function handleDeleteAsset() {
    if (!asset || !canDelete || !window.confirm(assetDeleteWarning(asset))) {
      return
    }
    deleteAssetMutation.mutate()
  }

  if (!asset) {
    return <StateMessage>Select an asset to see its metadata.</StateMessage>
  }

  const parent = asset.parent_id
    ? assets.find((candidate) => candidate.id === asset.parent_id) ?? null
    : null

  return (
    <div className="space-y-5">
      <dl className="grid gap-3 text-sm">
        <DetailRow label="Name">
          <span className="break-words font-medium">{asset.name}</span>
        </DetailRow>
        <DetailRow label="Type">
          <Badge variant={asset.type === scanTargetType ? "default" : "outline"}>
            {assetBadgeLabel(asset)}
          </Badge>
        </DetailRow>
        <DetailRow label="Path">
          <span className="break-words">{asset.path || "None"}</span>
        </DetailRow>
        <DetailRow label={assetReferenceLabel(asset)}>
          <span className="break-words">{assetTargetRefLabel(asset)}</span>
        </DetailRow>
        <DetailRow label="Parent">
          <span className="break-words">
            {parent ? parent.name : asset.parent_id ? asset.parent_id : "Root"}
          </span>
        </DetailRow>
        <DetailRow label="SLA tracking">
          {project ? (
            <SlaOverrideValue asset={asset} assets={assets} kind="tracking" project={project} />
          ) : (
            <OverrideValue value={asset.sla_tracking_enabled} />
          )}
        </DetailRow>
        <DetailRow label="SLA reporting">
          {project ? (
            <SlaOverrideValue asset={asset} assets={assets} kind="reporting" project={project} />
          ) : (
            <OverrideValue value={asset.sla_reporting_enabled} />
          )}
        </DetailRow>
      </dl>

      <form
        className="space-y-3 border-t pt-4"
        onSubmit={(event) => {
          event.preventDefault()
          if (canSave) {
            updateAssetMutation.mutate()
          }
        }}
      >
        <div>
          <h2 className="text-sm font-medium">Edit Selected Asset</h2>
          <p className="text-xs text-muted-foreground">Update display name and SLA settings.</p>
        </div>
        <Input
          aria-label="Asset name"
          onChange={(event) => setName(event.target.value)}
          placeholder="Name"
          value={name}
        />
        <label className="grid gap-1 text-xs font-medium text-muted-foreground">
          SLA tracking
          <select
            className={selectClassName}
            onChange={(event) => setSlaTracking(event.target.value as OverrideSelectValue)}
            value={slaTracking}
          >
            <option value="inherit">Inherit</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
        </label>
        <label className="grid gap-1 text-xs font-medium text-muted-foreground">
          SLA reporting
          <select
            className={selectClassName}
            onChange={(event) => setSlaReporting(event.target.value as OverrideSelectValue)}
            value={slaReporting}
          >
            <option value="inherit">Inherit</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
        </label>
        {updateAssetMutation.isError ? (
          <StateMessage tone="error">{errorMessage(updateAssetMutation.error)}</StateMessage>
        ) : null}
        {deleteAssetMutation.isError ? (
          <StateMessage tone="error">{errorMessage(deleteAssetMutation.error)}</StateMessage>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button disabled={!canSave} size="sm" type="submit">
            <Save className="size-4" aria-hidden="true" />
            Save asset
          </Button>
          <Button
            disabled={!canDelete}
            onClick={handleDeleteAsset}
            size="sm"
            type="button"
            variant="outline"
          >
            <Trash2 className="size-4" aria-hidden="true" />
            Delete {assetTypeLabel(asset.type)}
          </Button>
        </div>
      </form>
    </div>
  )
}

function DetailRow({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="grid gap-1 border-b pb-3 last:border-b-0 last:pb-0">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  )
}

function OverrideValue({ value }: { value: boolean | null }) {
  if (value === null) {
    return <span className="text-muted-foreground">Inherited</span>
  }
  return <StatusPill enabled={value} />
}

function SlaOverrideValue({
  asset,
  assets,
  kind,
  project,
}: {
  asset: Asset
  assets: Asset[]
  kind: SlaOverrideKind
  project: Project
}) {
  return (
    <StatusPill
      enabled={effectiveAssetSlaValue(asset, assets, project, kind)}
      label={assetSlaOverrideLabel(asset, assets, project, kind)}
    />
  )
}

function StatusPill({ enabled, label }: { enabled: boolean; label?: string }) {
  const Icon = enabled ? CheckCircle2 : AlertCircle
  return (
    <span className="inline-flex items-center gap-1.5">
      <Icon
        className={cn("size-4", enabled ? "text-primary" : "text-muted-foreground")}
        aria-hidden="true"
      />
      <span>{label ?? (enabled ? "Enabled" : "Disabled")}</span>
    </span>
  )
}

function StateMessage({
  children,
  tone = "muted",
}: {
  children: ReactNode
  tone?: "muted" | "error"
}) {
  return (
    <p className={cn("text-sm", tone === "error" ? "text-destructive" : "text-muted-foreground")}>
      {children}
    </p>
  )
}

export function filterProjects(projects: Project[], query: string): Project[] {
  const normalizedQuery = normalizeSearchQuery(query)
  if (!normalizedQuery) {
    return projects
  }
  return projects.filter((project) =>
    searchMatches(normalizedQuery, [project.name, project.slug, project.description]),
  )
}

export function projectCountLabel(count: number): string {
  const noun = count === 1 ? "project" : "projects"
  return `${new Intl.NumberFormat().format(count)} ${noun}`
}

export function normalizeGracePercent(value: string, fallback: number): number {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return fallback
  }
  const parsed = Number.parseInt(trimmed, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

export function filterAssetTree(assets: Asset[], query: string): Asset[] {
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

export function projectDeleteWarning(project: Project): string {
  return [
    `Delete project "${project.name}" (${project.slug})?`,
    "This will permanently remove folders, assets, scans, imports, findings, comments, workflow, and history tied to this project.",
  ].join("\n\n")
}

export function assetDeleteWarning(asset: Asset): string {
  return [
    `Delete ${assetTypeLabel(asset.type)} "${asset.name}"?`,
    "This will permanently remove the selected node, descendants, scans, imports, and findings tied to them.",
  ].join("\n\n")
}

export function createFolderPathPlaceholder(selectedAsset: Asset | null, assets: Asset[]): string {
  const parentPath = selectedFolderPathForCreate(selectedAsset, assets)
  return parentPath ? `${parentPath}/new_folder` : "new_folder"
}

export function canCreateFolderForSelection(
  selectedProjectId: string,
  selectedAsset: Asset | null,
): boolean {
  if (!selectedProjectId) {
    return false
  }
  return selectedAsset === null || selectedAsset.type === folderType
}

function selectedFolderPathForCreate(selectedAsset: Asset | null, assets: Asset[]): string {
  if (!selectedAsset) {
    return ""
  }
  if (selectedAsset.type === folderType) {
    return selectedAsset.path
  }
  if (!selectedAsset.parent_id) {
    return ""
  }
  return assets.find((asset) => asset.id === selectedAsset.parent_id)?.path ?? ""
}

function flattenAssets(assets: Asset[]): AssetTreeRow[] {
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

  const rows: AssetTreeRow[] = []
  const visited = new Set<string>()
  const emittedGroups = new Set<string>()

  function visit(parentId: string, depth: number) {
    for (const asset of byParent.get(parentId) ?? []) {
      if (visited.has(asset.id)) {
        continue
      }
      visited.add(asset.id)
      let assetDepth = depth
      if (parentId === "root") {
        const pathGroups = pathGroupsForAsset(asset, depth, emittedGroups)
        rows.push(...pathGroups)
        assetDepth = depth + pathFolderDepth(asset.path)
      }
      rows.push({ kind: "asset", asset, depth: assetDepth })
      visit(asset.id, assetDepth + 1)
    }
  }

  visit("root", 0)

  const remainingAssets = assets.filter((asset) => !visited.has(asset.id)).sort(compareAssets)
  if (remainingAssets.length > 0) {
    rows.push({
      kind: "group",
      id: "path-orphans",
      name: "Additional path assets",
      path: "",
      depth: 0,
    })
    rows.push(...flattenPathOnlyAssets(remainingAssets, 1))
  }

  if (rows.length === assets.length) {
    return rows
  }

  return rows
}

function pathFolderDepth(path: string): number {
  return Math.max(0, path.split("/").filter(Boolean).length - 1)
}

function pathGroupsForAsset(
  asset: Asset,
  baseDepth: number,
  emittedGroups: Set<string>,
): AssetTreeRow[] {
  const segments = asset.path.split("/").filter(Boolean)
  const folderSegments = segments.slice(0, -1)
  let currentPath = ""

  return folderSegments.flatMap((segment, index) => {
    currentPath = currentPath ? `${currentPath}/${segment}` : segment
    if (emittedGroups.has(currentPath)) {
      return []
    }
    emittedGroups.add(currentPath)
    return [
      {
        kind: "group" as const,
        id: `path:${currentPath}`,
        name: segment,
        path: currentPath,
        depth: baseDepth + index,
      },
    ]
  })
}

function flattenPathOnlyAssets(assets: Asset[], baseDepth: number): AssetTreeRow[] {
  const sortedAssets = [...assets].sort((left, right) => left.path.localeCompare(right.path))
  const rows: AssetTreeRow[] = []
  const emittedGroups = new Set<string>()

  for (const asset of sortedAssets) {
    const segments = asset.path.split("/").filter(Boolean)
    const folderSegments = segments.slice(0, -1)
    let currentPath = ""

    folderSegments.forEach((segment, index) => {
      currentPath = currentPath ? `${currentPath}/${segment}` : segment
      if (!emittedGroups.has(currentPath)) {
        emittedGroups.add(currentPath)
        rows.push({
          kind: "group",
          id: `path:${currentPath}`,
          name: segment,
          path: currentPath,
          depth: baseDepth + index,
        })
      }
    })

    rows.push({
      kind: "asset",
      asset,
      depth: baseDepth + folderSegments.length,
    })
  }

  return rows
}

function compareAssets(left: Asset, right: Asset): number {
  return left.sort_order - right.sort_order || left.name.localeCompare(right.name)
}

export function canMoveAssetToParent(
  asset: Asset,
  parentId: string | null,
  assets: Asset[],
): boolean {
  if (parentId === null) {
    return true
  }
  if (asset.id === parentId) {
    return false
  }

  const parent = assets.find((candidate) => candidate.id === parentId)
  if (!parent || parent.type !== folderType) {
    return false
  }

  return !descendantAssetIds(asset.id, assets).has(parentId)
}

export function assetMovePayload(_asset: Asset, parentId: string | null): UpdateAssetParams {
  return { parent_id: parentId }
}

function descendantAssetIds(assetId: string, assets: Asset[]): Set<string> {
  const childrenByParent = new Map<string, Asset[]>()
  for (const asset of assets) {
    if (!asset.parent_id) {
      continue
    }
    const siblings = childrenByParent.get(asset.parent_id) ?? []
    siblings.push(asset)
    childrenByParent.set(asset.parent_id, siblings)
  }

  const descendants = new Set<string>()
  const stack = [...(childrenByParent.get(assetId) ?? [])]
  while (stack.length > 0) {
    const child = stack.pop()
    if (!child || descendants.has(child.id)) {
      continue
    }
    descendants.add(child.id)
    stack.push(...(childrenByParent.get(child.id) ?? []))
  }
  return descendants
}

function overrideToSelectValue(value: boolean | null): OverrideSelectValue {
  if (value === true) {
    return "enabled"
  }
  if (value === false) {
    return "disabled"
  }
  return "inherit"
}

function selectValueToOverride(value: OverrideSelectValue): boolean | null {
  if (value === "enabled") {
    return true
  }
  if (value === "disabled") {
    return false
  }
  return null
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed."
}

function normalizeSearchQuery(query: string): string {
  return query.trim().toLocaleLowerCase()
}

function searchMatches(query: string, fields: Array<string | null | undefined>): boolean {
  return fields.some((field) => field?.toLocaleLowerCase().includes(query))
}

function projectLabel(project: Project): string {
  return project.slug && project.slug !== project.name
    ? `${project.name} / ${project.slug}`
    : project.name
}

export function assetTypeLabel(type: string): string {
  if (type === scanTargetType) {
    return "Asset"
  }
  return titleCaseLabel(type.replaceAll("_", " "))
}

export function assetBadgeLabel(asset: Asset): string {
  return asset.scan_label ?? assetTypeLabel(asset.type)
}

export function assetTargetRefLabel(asset: Asset): string {
  if (asset.type === folderType) {
    return "N/A"
  }
  return asset.target_ref || "None"
}

export function assetReferenceLabel(asset: Asset): string {
  if (asset.scan_label === "Trivy Image Scan") {
    return "Image"
  }
  return "Target ref"
}

export function assetSlaOverrideLabel(
  asset: Asset,
  assets: Asset[],
  project: Project,
  kind: SlaOverrideKind,
): string {
  const ownValue = assetSlaOverrideValue(asset, kind)
  if (ownValue !== null) {
    return enabledLabel(ownValue)
  }
  const inheritedValue = inheritedAssetSlaValue(asset, assets, project, kind)
  return `${enabledLabel(inheritedValue.enabled)} (Inherited from ${inheritedValue.source})`
}

function effectiveAssetSlaValue(
  asset: Asset,
  assets: Asset[],
  project: Project,
  kind: SlaOverrideKind,
): boolean {
  const ownValue = assetSlaOverrideValue(asset, kind)
  if (ownValue !== null) {
    return ownValue
  }
  return inheritedAssetSlaValue(asset, assets, project, kind).enabled
}

function inheritedAssetSlaValue(
  asset: Asset,
  assets: Asset[],
  project: Project,
  kind: SlaOverrideKind,
): { enabled: boolean; source: string } {
  const assetsById = new Map(assets.map((candidate) => [candidate.id, candidate]))
  const visited = new Set<string>()
  let parentId = asset.parent_id

  while (parentId && !visited.has(parentId)) {
    visited.add(parentId)
    const parent = assetsById.get(parentId)
    if (!parent) {
      break
    }
    const parentValue = assetSlaOverrideValue(parent, kind)
    if (parentValue !== null) {
      return { enabled: parentValue, source: parent.name }
    }
    parentId = parent.parent_id
  }

  return {
    enabled: kind === "tracking" ? project.sla_tracking_enabled : project.sla_reporting_enabled,
    source: project.name,
  }
}

function assetSlaOverrideValue(asset: Asset, kind: SlaOverrideKind): boolean | null {
  return kind === "tracking" ? asset.sla_tracking_enabled : asset.sla_reporting_enabled
}

function enabledLabel(enabled: boolean): string {
  return enabled ? "Enabled" : "Disabled"
}

function titleCaseLabel(label: string): string {
  return label.replace(/\b\w/g, (character) => character.toLocaleUpperCase())
}
