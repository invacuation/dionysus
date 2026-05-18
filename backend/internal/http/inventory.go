package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

var whitespaceRE = regexp.MustCompile(`\s`)

type projectResponse struct {
	ID                                string  `json:"id"`
	Slug                              string  `json:"slug"`
	Name                              string  `json:"name"`
	Description                       *string `json:"description"`
	SLATrackingEnabled                bool    `json:"sla_tracking_enabled"`
	SLAReportingEnabled               bool    `json:"sla_reporting_enabled"`
	RequirePeerReviewForStatusChanges bool    `json:"require_peer_review_for_status_changes"`
	GracePeriodEnabled                bool    `json:"grace_period_enabled"`
	GracePeriodPercent                int64   `json:"grace_period_percent"`
}

type projectListResponse struct {
	Projects []projectResponse `json:"projects"`
}

type assetResponse struct {
	ID                  string  `json:"id"`
	ParentID            *string `json:"parent_id"`
	Path                string  `json:"path"`
	Type                string  `json:"type"`
	Name                string  `json:"name"`
	TargetRef           *string `json:"target_ref"`
	ScanLabel           *string `json:"scan_label"`
	SLATrackingEnabled  *bool   `json:"sla_tracking_enabled"`
	SLAReportingEnabled *bool   `json:"sla_reporting_enabled"`
	GracePeriodEnabled  *bool   `json:"grace_period_enabled"`
	GracePeriodPercent  *int64  `json:"grace_period_percent"`
	SortOrder           int64   `json:"sort_order"`
}

type projectAssetsResponse struct {
	ProjectID string          `json:"project_id"`
	Assets    []assetResponse `json:"assets"`
}

type projectCreateRequest struct {
	Slug                              string  `json:"slug"`
	Name                              string  `json:"name"`
	Description                       *string `json:"description"`
	SLATrackingEnabled                *bool   `json:"sla_tracking_enabled"`
	SLAReportingEnabled               *bool   `json:"sla_reporting_enabled"`
	RequirePeerReviewForStatusChanges *bool   `json:"require_peer_review_for_status_changes"`
	GracePeriodEnabled                *bool   `json:"grace_period_enabled"`
	GracePeriodPercent                *int64  `json:"grace_period_percent"`
}

func mountInventoryRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Get("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		listProjects(w, r, settings, deps)
	})
	router.Post("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		createProject(w, r, settings, deps)
	})
	router.Patch("/api/projects/{projectID}", func(w http.ResponseWriter, r *http.Request) {
		updateProject(w, r, settings, deps)
	})
	router.Delete("/api/projects/{projectID}", func(w http.ResponseWriter, r *http.Request) {
		deleteProject(w, r, settings, deps)
	})
	router.Get("/api/projects/{projectID}/assets", func(w http.ResponseWriter, r *http.Request) {
		listProjectAssets(w, r, settings, deps)
	})
	router.Post("/api/projects/{projectID}/folders", func(w http.ResponseWriter, r *http.Request) {
		resolveFolder(w, r, settings, deps)
	})
	router.Post("/api/projects/{projectID}/scan-targets", func(w http.ResponseWriter, r *http.Request) {
		createScanTarget(w, r, settings, deps)
	})
	router.Patch("/api/projects/{projectID}/assets/{assetID}", func(w http.ResponseWriter, r *http.Request) {
		updateAsset(w, r, settings, deps)
	})
	router.Delete("/api/projects/{projectID}/assets/{assetID}", func(w http.ResponseWriter, r *http.Request) {
		deleteAsset(w, r, settings, deps)
	})
}

func listProjects(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := authenticatedActorFromRequest(w, r, settings, deps)
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	projects, err := queries.ListProjects(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response := projectListResponse{Projects: []projectResponse{}}
	for _, project := range projects {
		if _, err := identity.EnsureActorPermission(r.Context(), deps.DB, *actor, identity.PermissionRequest{
			Permission: "project:view",
			ScopeType:  stringPtr("project"),
			ScopeID:    stringPtr(project.ID),
		}); err == nil {
			response.Projects = append(response.Projects, projectResponseFromDB(project))
		} else if !errors.Is(err, identity.ErrForbidden) {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func createProject(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "project:create"})
	if !ok {
		return
	}
	var payload projectCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid project request")
		return
	}
	slug, name, err := validateProjectIdentity(payload.Slug, payload.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gracePeriodPercent := int64(100)
	if payload.GracePeriodPercent != nil {
		gracePeriodPercent = *payload.GracePeriodPercent
	}
	if gracePeriodPercent <= 0 {
		writeError(w, http.StatusBadRequest, "grace period percent must be positive")
		return
	}
	now := time.Now().UTC()
	project, err := dbgen.New(deps.DB).CreateProject(r.Context(), dbgen.CreateProjectParams{
		ID:                                uuid.NewString(),
		Slug:                              slug,
		Name:                              name,
		Description:                       nullStringFromPtr(payload.Description),
		SlaTrackingEnabled:                boolDefault(payload.SLATrackingEnabled, true),
		SlaReportingEnabled:               boolDefault(payload.SLAReportingEnabled, true),
		GracePeriodEnabled:                boolDefault(payload.GracePeriodEnabled, false),
		GracePeriodPercent:                gracePeriodPercent,
		RequirePeerReviewForStatusChanges: boolDefault(payload.RequirePeerReviewForStatusChanges, false),
		CreatedAt:                         now,
		UpdatedAt:                         now,
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Project slug or name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "inventory.project.create",
		TargetType: stringPtr("project"),
		TargetID:   stringPtr(project.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"slug": project.Slug,
			"name": project.Name,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, projectResponseFromDB(project))
}

func updateProject(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "project:update", ScopeType: stringPtr("project"), ScopeID: stringPtr(projectID)})
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	project, err := queries.GetProject(r.Context(), projectID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Project not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	payload := map[string]json.RawMessage{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid project request")
		return
	}
	changes := map[string]map[string]any{}
	if raw, exists := payload["slug"]; exists {
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			writeError(w, http.StatusBadRequest, "project slug must be non-empty")
			return
		}
		slug, err := validateProjectSlug(*value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if slug != project.Slug {
			changes["slug"] = change(project.Slug, slug)
			project.Slug = slug
		}
	}
	if raw, exists := payload["name"]; exists {
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			writeError(w, http.StatusBadRequest, "project name must be non-empty")
			return
		}
		name, err := validateProjectName(*value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if name != project.Name {
			changes["name"] = change(project.Name, name)
			project.Name = name
		}
	}
	if !applyBoolProjectPatch(w, payload, "sla_tracking_enabled", project.SlaTrackingEnabled, &project.SlaTrackingEnabled, changes) {
		return
	}
	if !applyBoolProjectPatch(w, payload, "sla_reporting_enabled", project.SlaReportingEnabled, &project.SlaReportingEnabled, changes) {
		return
	}
	if !applyBoolProjectPatch(w, payload, "require_peer_review_for_status_changes", project.RequirePeerReviewForStatusChanges, &project.RequirePeerReviewForStatusChanges, changes) {
		return
	}
	if !applyBoolProjectPatch(w, payload, "grace_period_enabled", project.GracePeriodEnabled, &project.GracePeriodEnabled, changes) {
		return
	}
	if raw, exists := payload["grace_period_percent"]; exists {
		var value *int64
		if err := json.Unmarshal(raw, &value); err != nil || value == nil || *value <= 0 {
			writeError(w, http.StatusBadRequest, "grace_period_percent must be a positive integer")
			return
		}
		if *value != project.GracePeriodPercent {
			changes["grace_period_percent"] = change(project.GracePeriodPercent, *value)
			project.GracePeriodPercent = *value
		}
	}
	if _, err := queries.GetProjectIdentityConflict(r.Context(), dbgen.GetProjectIdentityConflictParams{
		ID:   project.ID,
		Slug: project.Slug,
		Name: project.Name,
	}); err == nil {
		writeError(w, http.StatusConflict, "Project slug or name already exists")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	updated, err := queries.UpdateProject(r.Context(), dbgen.UpdateProjectParams{
		ID:                                project.ID,
		Slug:                              project.Slug,
		Name:                              project.Name,
		SlaTrackingEnabled:                project.SlaTrackingEnabled,
		SlaReportingEnabled:               project.SlaReportingEnabled,
		GracePeriodEnabled:                project.GracePeriodEnabled,
		GracePeriodPercent:                project.GracePeriodPercent,
		RequirePeerReviewForStatusChanges: project.RequirePeerReviewForStatusChanges,
		UpdatedAt:                         time.Now().UTC(),
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Project slug or name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if len(changes) > 0 {
		if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
			Type:       "inventory.project.update",
			TargetType: stringPtr("project"),
			TargetID:   stringPtr(updated.ID),
			ProjectID:  stringPtr(updated.ID),
			Metadata: map[string]any{
				"changed_fields": orderedChangedFields(payload, changes),
				"changes":        changes,
			},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	writeJSON(w, http.StatusOK, projectResponseFromDB(updated))
}

func deleteProject(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "project:delete", ScopeType: stringPtr("project"), ScopeID: stringPtr(projectID)})
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	project, err := queries.GetProject(r.Context(), projectID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Project not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	assetCount, err := queries.CountProjectAssets(r.Context(), project.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "inventory.project.delete",
		TargetType: stringPtr("project"),
		TargetID:   stringPtr(project.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"slug":                project.Slug,
			"name":                project.Name,
			"deleted_asset_count": assetCount,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := queries.DeleteProjectAssets(r.Context(), project.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := queries.DeleteProject(r.Context(), project.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func listProjectAssets(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "project:view", ScopeType: stringPtr("project"), ScopeID: stringPtr(projectID)}); !ok {
		return
	}
	if _, ok := getProjectForInventory(w, r, deps, projectID); !ok {
		return
	}
	assets, err := dbgen.New(deps.DB).ListProjectAssets(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response := projectAssetsResponse{ProjectID: projectID, Assets: make([]assetResponse, 0, len(assets))}
	for _, asset := range assets {
		response.Assets = append(response.Assets, assetResponseFromDB(asset))
	}
	writeJSON(w, http.StatusOK, response)
}

func resolveFolder(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	actor, project, ok := requireProjectPermission(w, r, settings, deps, projectID, "asset:create")
	if !ok {
		return
	}
	var payload struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid folder request")
		return
	}
	folder, err := resolveFolderPath(r, deps, project.ID, payload.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "inventory.folder.resolve",
		TargetType: stringPtr("asset_node"),
		TargetID:   stringPtr(folder.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"path": folder.Path,
			"name": folder.Name,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, assetResponseFromDB(folder))
}

func createScanTarget(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	actor, project, ok := requireProjectPermission(w, r, settings, deps, projectID, "asset:create")
	if !ok {
		return
	}
	var payload struct {
		FolderPath string         `json:"folder_path"`
		Name       string         `json:"name"`
		TargetRef  string         `json:"target_ref"`
		NodeType   string         `json:"node_type"`
		Metadata   map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid scan target request")
		return
	}
	nodeType := payload.NodeType
	if nodeType == "" {
		nodeType = "scan_target"
	}
	if !targetLikeNodeType(nodeType) {
		writeError(w, http.StatusBadRequest, "scan target node type must be target-like")
		return
	}
	parent, err := resolveFolderPath(r, deps, project.ID, payload.FolderPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := validateAssetName(payload.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	targetRef := strings.TrimSpace(payload.TargetRef)
	if targetRef == "" {
		writeError(w, http.StatusBadRequest, "asset target_ref must be non-empty")
		return
	}
	path := childPath(parent.Path, name)
	metadataJSON, _ := json.Marshal(payload.Metadata)
	if string(metadataJSON) == "null" {
		metadataJSON = []byte("{}")
	}
	now := time.Now().UTC()
	target, err := dbgen.New(deps.DB).CreateAssetNode(r.Context(), dbgen.CreateAssetNodeParams{
		ID:           uuid.NewString(),
		ProjectID:    project.ID,
		ParentID:     sql.NullString{String: parent.ID, Valid: true},
		NodeType:     nodeType,
		Name:         name,
		Path:         path,
		TargetRef:    sql.NullString{String: targetRef, Valid: true},
		MetadataJson: string(metadataJSON),
		SortOrder:    0,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Asset path or sibling name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "inventory.scan_target.create",
		TargetType: stringPtr("asset_node"),
		TargetID:   stringPtr(target.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"folder_path": parent.Path,
			"name":        target.Name,
			"node_type":   target.NodeType,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusCreated, assetResponseFromDB(target))
}

func updateAsset(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	assetID := chi.URLParam(r, "assetID")
	actor, project, ok := requireProjectPermission(w, r, settings, deps, projectID, "asset:update")
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	asset, ok := getProjectAssetForInventory(w, r, queries, project.ID, assetID)
	if !ok {
		return
	}
	payload := map[string]json.RawMessage{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Invalid asset request")
		return
	}
	changed := []string{}
	oldPath := asset.Path
	parentID := asset.ParentID
	if raw, exists := payload["parent_id"]; exists {
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid asset request")
			return
		}
		parentID = nullStringFromPtr(value)
		if value != nil {
			parent, err := queries.GetAssetNode(r.Context(), *value)
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusBadRequest, "asset parent must belong to the same project")
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if parent.ProjectID != project.ID {
				writeError(w, http.StatusBadRequest, "asset parent must belong to the same project")
				return
			}
			if parent.ID == asset.ID || strings.HasPrefix(parent.Path, asset.Path+"/") {
				writeError(w, http.StatusBadRequest, "cannot move an asset node under one of its descendants")
				return
			}
			asset.Path = childPath(parent.Path, asset.Name)
		} else {
			asset.Path = asset.Name
		}
		changed = append(changed, "parent_id")
	}
	if raw, exists := payload["name"]; exists {
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			writeError(w, http.StatusBadRequest, "asset node name must be non-empty")
			return
		}
		name, err := validateAssetName(*value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		asset.Name = name
		parentPath := ""
		if parentID.Valid {
			parent, err := queries.GetAssetNode(r.Context(), parentID.String)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			parentPath = parent.Path
		}
		asset.Path = childPath(parentPath, name)
		changed = append(changed, "name")
	}
	if !applyNullBoolPatch(w, payload, "sla_tracking_enabled", &asset.SlaTrackingEnabled, &changed) {
		return
	}
	if !applyNullBoolPatch(w, payload, "sla_reporting_enabled", &asset.SlaReportingEnabled, &changed) {
		return
	}
	if !applyNullBoolPatch(w, payload, "grace_period_enabled", &asset.GracePeriodEnabled, &changed) {
		return
	}
	if raw, exists := payload["grace_period_percent"]; exists {
		var value *int64
		if err := json.Unmarshal(raw, &value); err != nil || (value != nil && *value <= 0) {
			writeError(w, http.StatusBadRequest, "grace_period_percent must be a positive integer")
			return
		}
		asset.GracePeriodPercent = nullIntFromPtr(value)
		changed = append(changed, "grace_period_percent")
	}
	updated, err := queries.UpdateAssetNode(r.Context(), dbgen.UpdateAssetNodeParams{
		ID:                  asset.ID,
		ParentID:            parentID,
		Name:                asset.Name,
		Path:                asset.Path,
		SlaTrackingEnabled:  asset.SlaTrackingEnabled,
		SlaReportingEnabled: asset.SlaReportingEnabled,
		GracePeriodEnabled:  asset.GracePeriodEnabled,
		GracePeriodPercent:  asset.GracePeriodPercent,
		UpdatedAt:           time.Now().UTC(),
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			writeError(w, http.StatusConflict, "Asset path or sibling name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if updated.Path != oldPath {
		subtree, err := queries.ListAssetSubtree(r.Context(), dbgen.ListAssetSubtreeParams{ProjectID: project.ID, ID: updated.ID, Path: oldPath + "/%"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		now := time.Now().UTC()
		for _, descendant := range subtree {
			if descendant.ID == updated.ID {
				continue
			}
			newPath := updated.Path + strings.TrimPrefix(descendant.Path, oldPath)
			if err := queries.UpdateAssetPath(r.Context(), dbgen.UpdateAssetPathParams{ID: descendant.ID, Path: newPath, UpdatedAt: now}); err != nil {
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
	}
	if len(changed) > 0 {
		if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
			Type:       "inventory.asset.update",
			TargetType: stringPtr("asset_node"),
			TargetID:   stringPtr(updated.ID),
			ProjectID:  stringPtr(project.ID),
			Metadata:   map[string]any{"changed_fields": changed},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	writeJSON(w, http.StatusOK, assetResponseFromDB(updated))
}

func deleteAsset(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	projectID := chi.URLParam(r, "projectID")
	assetID := chi.URLParam(r, "assetID")
	actor, project, ok := requireProjectPermission(w, r, settings, deps, projectID, "asset:delete")
	if !ok {
		return
	}
	queries := dbgen.New(deps.DB)
	asset, ok := getProjectAssetForInventory(w, r, queries, project.ID, assetID)
	if !ok {
		return
	}
	subtree, err := queries.ListAssetSubtree(r.Context(), dbgen.ListAssetSubtreeParams{ProjectID: project.ID, ID: asset.ID, Path: asset.Path + "/%"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "inventory.asset.delete",
		TargetType: stringPtr("asset_node"),
		TargetID:   stringPtr(asset.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"path":               asset.Path,
			"name":               asset.Name,
			"node_type":          asset.NodeType,
			"deleted_node_count": len(subtree),
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := queries.DeleteAssetSubtree(r.Context(), dbgen.DeleteAssetSubtreeParams{ProjectID: project.ID, ID: asset.ID, Path: asset.Path + "/%"}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func projectResponseFromDB(project dbgen.Project) projectResponse {
	return projectResponse{
		ID:                                project.ID,
		Slug:                              project.Slug,
		Name:                              project.Name,
		Description:                       optionalStringFromNull(project.Description),
		SLATrackingEnabled:                project.SlaTrackingEnabled,
		SLAReportingEnabled:               project.SlaReportingEnabled,
		RequirePeerReviewForStatusChanges: project.RequirePeerReviewForStatusChanges,
		GracePeriodEnabled:                project.GracePeriodEnabled,
		GracePeriodPercent:                project.GracePeriodPercent,
	}
}

func assetResponseFromDB(asset dbgen.AssetNode) assetResponse {
	return assetResponse{
		ID:                  asset.ID,
		ParentID:            optionalStringFromNull(asset.ParentID),
		Path:                asset.Path,
		Type:                asset.NodeType,
		Name:                asset.Name,
		TargetRef:           optionalStringFromNull(asset.TargetRef),
		ScanLabel:           nil,
		SLATrackingEnabled:  optionalBoolFromNull(asset.SlaTrackingEnabled),
		SLAReportingEnabled: optionalBoolFromNull(asset.SlaReportingEnabled),
		GracePeriodEnabled:  optionalBoolFromNull(asset.GracePeriodEnabled),
		GracePeriodPercent:  optionalIntFromNull(asset.GracePeriodPercent),
		SortOrder:           asset.SortOrder,
	}
}

func requireProjectPermission(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies, projectID string, permission string) (*identity.AuthenticatedActor, dbgen.Project, bool) {
	project, ok := getProjectForInventory(w, r, deps, projectID)
	if !ok {
		return nil, dbgen.Project{}, false
	}
	actor, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: permission, ScopeType: stringPtr("project"), ScopeID: stringPtr(project.ID)})
	if !ok {
		return nil, dbgen.Project{}, false
	}
	return actor, project, true
}

func getProjectForInventory(w http.ResponseWriter, r *http.Request, deps Dependencies, projectID string) (dbgen.Project, bool) {
	project, err := dbgen.New(deps.DB).GetProject(r.Context(), projectID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "Project not found")
		return dbgen.Project{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return dbgen.Project{}, false
	}
	return project, true
}

func getProjectAssetForInventory(w http.ResponseWriter, r *http.Request, queries *dbgen.Queries, projectID string, assetID string) (dbgen.AssetNode, bool) {
	asset, err := queries.GetAssetNode(r.Context(), assetID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && asset.ProjectID != projectID) {
		writeError(w, http.StatusNotFound, "Asset not found")
		return dbgen.AssetNode{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return dbgen.AssetNode{}, false
	}
	return asset, true
}

func resolveFolderPath(r *http.Request, deps Dependencies, projectID string, path string) (dbgen.AssetNode, error) {
	normalized, err := normalizeFolderPath(path)
	if err != nil {
		return dbgen.AssetNode{}, err
	}
	queries := dbgen.New(deps.DB)
	var parent *dbgen.AssetNode
	currentPath := ""
	for _, segment := range strings.Split(normalized, "/") {
		if parent == nil {
			currentPath = segment
		} else {
			currentPath = childPath(parent.Path, segment)
		}
		folder, err := queries.GetProjectAssetByPath(r.Context(), dbgen.GetProjectAssetByPathParams{ProjectID: projectID, Path: currentPath})
		if err == nil {
			if folder.NodeType != "folder" {
				return dbgen.AssetNode{}, errors.New("folder path conflicts with existing asset node")
			}
			parent = &folder
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return dbgen.AssetNode{}, err
		}
		now := time.Now().UTC()
		parentID := sql.NullString{}
		if parent != nil {
			parentID = sql.NullString{String: parent.ID, Valid: true}
		}
		created, err := queries.CreateAssetNode(r.Context(), dbgen.CreateAssetNodeParams{
			ID:           uuid.NewString(),
			ProjectID:    projectID,
			ParentID:     parentID,
			NodeType:     "folder",
			Name:         segment,
			Path:         currentPath,
			MetadataJson: "{}",
			SortOrder:    0,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return dbgen.AssetNode{}, err
		}
		parent = &created
	}
	if parent == nil {
		return dbgen.AssetNode{}, errors.New("folder path must be non-empty")
	}
	return *parent, nil
}

func normalizeFolderPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("folder path must be non-empty")
	}
	segments := []string{}
	for _, raw := range strings.Split(path, "/") {
		segment := strings.TrimSpace(raw)
		if segment == "" {
			return "", errors.New("folder path must not contain empty segments")
		}
		if segment == "." || segment == ".." {
			return "", errors.New("folder path must not contain relative segments")
		}
		segments = append(segments, segment)
	}
	return strings.Join(segments, "/"), nil
}

func validateAssetName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("asset node name must be non-empty")
	}
	if strings.Contains(trimmed, "/") {
		return "", errors.New("asset node name must not contain path separators")
	}
	if trimmed == "." || trimmed == ".." {
		return "", errors.New("asset node name must not be a relative segment")
	}
	return trimmed, nil
}

func childPath(parentPath string, name string) string {
	if parentPath == "" {
		return name
	}
	return parentPath + "/" + name
}

func targetLikeNodeType(nodeType string) bool {
	switch nodeType {
	case "branch", "release", "tag", "container_image", "manifest", "file", "scan_target", "other":
		return true
	default:
		return false
	}
}

func applyNullBoolPatch(w http.ResponseWriter, payload map[string]json.RawMessage, name string, target *sql.NullBool, changed *[]string) bool {
	raw, exists := payload[name]
	if !exists {
		return true
	}
	var value *bool
	if err := json.Unmarshal(raw, &value); err != nil {
		writeError(w, http.StatusBadRequest, name+" must be a boolean")
		return false
	}
	if value == nil {
		*target = sql.NullBool{}
	} else {
		*target = sql.NullBool{Bool: *value, Valid: true}
	}
	*changed = append(*changed, name)
	return true
}

func optionalBoolFromNull(value sql.NullBool) *bool {
	if !value.Valid {
		return nil
	}
	return &value.Bool
}

func optionalIntFromNull(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	return &value.Int64
}

func nullIntFromPtr(value *int64) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *value, Valid: true}
}

func validateProjectIdentity(slug string, name string) (string, string, error) {
	validSlug, err := validateProjectSlug(slug)
	if err != nil {
		return "", "", err
	}
	validName, err := validateProjectName(name)
	if err != nil {
		return "", "", err
	}
	return validSlug, validName, nil
}

func validateProjectSlug(slug string) (string, error) {
	if slug == "" {
		return "", errors.New("project slug must be non-empty")
	}
	if whitespaceRE.MatchString(slug) {
		return "", errors.New("project slug must not contain whitespace")
	}
	return slug, nil
}

func validateProjectName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("project name must be non-empty")
	}
	return trimmed, nil
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func applyBoolProjectPatch(w http.ResponseWriter, payload map[string]json.RawMessage, name string, old bool, target *bool, changes map[string]map[string]any) bool {
	raw, exists := payload[name]
	if !exists {
		return true
	}
	var value *bool
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		writeError(w, http.StatusBadRequest, name+" must be a boolean")
		return false
	}
	if *value != old {
		changes[name] = change(old, *value)
		*target = *value
	}
	return true
}

func change(old any, next any) map[string]any {
	return map[string]any{"old": old, "new": next}
}

func orderedChangedFields(payload map[string]json.RawMessage, changes map[string]map[string]any) []string {
	order := []string{
		"slug",
		"name",
		"sla_tracking_enabled",
		"sla_reporting_enabled",
		"require_peer_review_for_status_changes",
		"grace_period_enabled",
		"grace_period_percent",
	}
	fields := make([]string, 0, len(changes))
	for _, field := range order {
		if _, inPayload := payload[field]; !inPayload {
			continue
		}
		if _, changed := changes[field]; changed {
			fields = append(fields, field)
		}
	}
	return fields
}
