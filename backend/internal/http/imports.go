package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	auditlog "github.com/invacuation/dionysus/backend/internal/audit"
	"github.com/invacuation/dionysus/backend/internal/config"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
	"github.com/invacuation/dionysus/backend/internal/identity"
)

const (
	trivyScanner       = "trivy"
	trivyReportKind    = "trivy-image-json"
	trivyParserVersion = "1.0"
)

type trivyPreviewResponse struct {
	Scanner             string     `json:"scanner"`
	ReportKind          string     `json:"report_kind"`
	ToolLabel           string     `json:"tool_label"`
	DetectedProjectName string     `json:"detected_project_name"`
	DetectedAssetName   string     `json:"detected_asset_name"`
	DetectedTargetRef   string     `json:"detected_target_ref"`
	ScanStartedAt       *time.Time `json:"scan_started_at"`
	FindingCount        int        `json:"finding_count"`
	GroupCount          int        `json:"group_count"`
}

type trivyImportResponse struct {
	ImportAttemptID string `json:"import_attempt_id"`
	ScanID          string `json:"scan_id"`
	ProjectID       string `json:"project_id"`
	ScanTargetID    string `json:"scan_target_id"`
	Scanner         string `json:"scanner"`
	ReportKind      string `json:"report_kind"`
	FindingCount    int    `json:"finding_count"`
	GroupCount      int    `json:"group_count"`
}

type adminImportHistoryResponse struct {
	Attempts []adminImportAttemptResponse `json:"attempts"`
}

type adminImportAttemptResponse struct {
	ID                    string         `json:"id"`
	ProjectID             string         `json:"project_id"`
	ProjectName           string         `json:"project_name"`
	AssetID               *string        `json:"asset_id"`
	AssetName             *string        `json:"asset_name"`
	AssetPath             *string        `json:"asset_path"`
	UploaderPrincipalType *string        `json:"uploader_principal_type"`
	UploaderPrincipalID   *string        `json:"uploader_principal_id"`
	UploaderDisplay       *string        `json:"uploader_display"`
	Status                string         `json:"status"`
	ParserName            string         `json:"parser_name"`
	SanitizedMessage      *string        `json:"sanitized_message"`
	CorrelationID         *string        `json:"correlation_id"`
	Metadata              map[string]any `json:"metadata"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

type parsedTrivyReport struct {
	Target        string
	ScanStartedAt *time.Time
	Findings      []parsedFinding
}

type parsedFinding struct {
	ScannerFindingID  string
	PrimaryIdentifier string
	Identifiers       []string
	Severity          string
	PackageName       *string
	PackageVersion    *string
	FixedVersion      *string
	PackagePath       *string
	ArtifactName      *string
	ArtifactType      *string
	ArtifactPath      *string
	DedupeKey         string
	References        []string
	Source            map[string]any
	CVSS              map[string]any
}

func mountImportRoutes(router chi.Router, settings config.Settings, deps Dependencies) {
	router.Post("/api/imports/trivy/preview", func(w http.ResponseWriter, r *http.Request) {
		previewTrivy(w, r, settings, deps)
	})
	router.Post("/api/imports/trivy", func(w http.ResponseWriter, r *http.Request) {
		importTrivy(w, r, settings, deps)
	})
	router.Get("/api/admin/imports", func(w http.ResponseWriter, r *http.Request) {
		listAdminImports(w, r, settings, deps)
	})
}

func listAdminImports(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	if _, ok := requireActorPermission(w, r, settings, deps, identity.PermissionRequest{Permission: "import:history:view"}); !ok {
		return
	}
	rows, err := dbgen.New(deps.DB).ListAdminImportAttempts(r.Context(), importHistoryLimit(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	attempts := make([]adminImportAttemptResponse, 0, len(rows))
	for _, row := range rows {
		attempt, err := adminImportAttemptResponseFromDB(row)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		attempts = append(attempts, attempt)
	}
	writeJSON(w, http.StatusOK, adminImportHistoryResponse{Attempts: attempts})
}

func previewTrivy(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	payload, projectID, ok := readTrivyUpload(w, r, settings)
	if !ok {
		return
	}
	if _, _, ok := requireProjectPermission(w, r, settings, deps, projectID, "import:upload"); !ok {
		return
	}
	report, err := parseTrivyImageJSON(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, previewResponseFromReport(report))
}

func importTrivy(w http.ResponseWriter, r *http.Request, settings config.Settings, deps Dependencies) {
	payload, projectID, ok := readTrivyUpload(w, r, settings)
	if !ok {
		return
	}
	actor, project, ok := requireProjectPermission(w, r, settings, deps, projectID, "import:upload")
	if !ok {
		return
	}
	scanTargetID := strings.TrimSpace(r.FormValue("scan_target_id"))
	folderID := strings.TrimSpace(r.FormValue("folder_id"))
	folderPath := strings.TrimSpace(r.FormValue("folder_path"))
	if scanTargetID != "" && (folderID != "" || folderPath != "") {
		writeError(w, http.StatusBadRequest, "Provide either scan_target_id or folder_id/folder_path, not both")
		return
	}
	if folderID != "" && folderPath != "" {
		writeError(w, http.StatusBadRequest, "Provide either folder_id or folder_path, not both")
		return
	}
	queries := dbgen.New(deps.DB)
	startedAt, ok := parseOptionalScanTime(w, r.FormValue("scan_started_at"))
	if !ok {
		return
	}
	report, err := parseTrivyImageJSON(payload)
	if err != nil {
		failedTargetID := scanTargetID
		attempt := createFailedImportAttempt(w, r, deps, project.ID, failedTargetID, *actor, err.Error())
		if attempt == nil {
			return
		}
		targetType := "scan_target"
		auditTargetID := failedTargetID
		var metadataScanTargetID any = failedTargetID
		if scanTargetID == "" {
			targetType = "project"
			auditTargetID = project.ID
			metadataScanTargetID = nil
		}
		if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
			Type:       "import.trivy.failure",
			TargetType: stringPtr(targetType),
			TargetID:   stringPtr(auditTargetID),
			ProjectID:  stringPtr(project.ID),
			Metadata: map[string]any{
				"scan_target_id":   metadataScanTargetID,
				"failure_category": "parser_error",
				"detail":           err.Error(),
			},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scanTarget, ok := resolveImportScanTarget(w, r, deps, queries, project.ID, scanTargetID, folderID, folderPath, report)
	if !ok {
		return
	}
	if startedAt == nil {
		startedAt = report.ScanStartedAt
	}
	result, err := persistTrivyImport(r, deps, project.ID, scanTarget.ID, *actor, report, startedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := recordActorAuditEvent(r, deps, *actor, auditlog.Event{
		Type:       "import.trivy.success",
		TargetType: stringPtr("scan_target"),
		TargetID:   stringPtr(scanTarget.ID),
		ProjectID:  stringPtr(project.ID),
		Metadata: map[string]any{
			"scan_target_id": scanTarget.ID,
			"finding_count":  len(report.Findings),
			"group_count":    groupCount(report),
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeJSON(w, http.StatusOK, trivyImportResponse{
		ImportAttemptID: result.attempt.ID,
		ScanID:          result.scan.ID,
		ProjectID:       project.ID,
		ScanTargetID:    scanTarget.ID,
		Scanner:         trivyScanner,
		ReportKind:      trivyReportKind,
		FindingCount:    len(report.Findings),
		GroupCount:      groupCount(report),
	})
}

func resolveImportScanTarget(w http.ResponseWriter, r *http.Request, deps Dependencies, queries *dbgen.Queries, projectID string, scanTargetID string, folderID string, folderPath string, report parsedTrivyReport) (dbgen.AssetNode, bool) {
	if scanTargetID != "" {
		scanTarget, ok := getProjectAssetForInventory(w, r, queries, projectID, scanTargetID)
		if !ok {
			return dbgen.AssetNode{}, false
		}
		if scanTarget.NodeType != "scan_target" {
			writeError(w, http.StatusNotFound, "Scan target not found")
			return dbgen.AssetNode{}, false
		}
		return scanTarget, true
	}

	var folder *dbgen.AssetNode
	if folderID != "" {
		resolved, ok := getProjectAssetForInventory(w, r, queries, projectID, folderID)
		if !ok {
			return dbgen.AssetNode{}, false
		}
		if resolved.NodeType != "folder" {
			writeError(w, http.StatusNotFound, "Folder not found")
			return dbgen.AssetNode{}, false
		}
		folder = &resolved
	} else if folderPath != "" {
		resolved, err := resolveFolderPath(r, deps, projectID, folderPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return dbgen.AssetNode{}, false
		}
		folder = &resolved
	}

	scanTarget, err := createOrReuseImportScanTarget(r, queries, projectID, folder, r.FormValue("asset_name"), r.FormValue("target_ref"), report)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return dbgen.AssetNode{}, false
	}
	return scanTarget, true
}

func createOrReuseImportScanTarget(r *http.Request, queries *dbgen.Queries, projectID string, folder *dbgen.AssetNode, assetName string, targetRef string, report parsedTrivyReport) (dbgen.AssetNode, error) {
	resolvedTargetRef := strings.TrimSpace(targetRef)
	if resolvedTargetRef == "" {
		resolvedTargetRef = strings.TrimSpace(report.Target)
	}
	resolvedAssetName := strings.TrimSpace(assetName)
	if resolvedAssetName == "" {
		resolvedAssetName = resolvedTargetRef
	}
	if resolvedAssetName == "" || resolvedTargetRef == "" {
		return dbgen.AssetNode{}, errors.New("asset_name or detected report target is required")
	}
	name, err := validateAssetName(resolvedAssetName)
	if err != nil {
		return dbgen.AssetNode{}, err
	}
	parentID := sql.NullString{}
	parentPath := ""
	if folder != nil {
		parentID = sql.NullString{String: folder.ID, Valid: true}
		parentPath = folder.Path
	}
	existingByRef, err := queries.GetProjectTargetByParentAndTargetRef(r.Context(), dbgen.GetProjectTargetByParentAndTargetRefParams{
		ProjectID: projectID,
		NodeType:  "scan_target",
		TargetRef: sql.NullString{String: resolvedTargetRef, Valid: true},
		ParentID:  parentID,
	})
	if err == nil {
		return existingByRef, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return dbgen.AssetNode{}, err
	}
	existingByName, err := queries.GetProjectAssetByParentAndName(r.Context(), dbgen.GetProjectAssetByParentAndNameParams{
		ProjectID: projectID,
		Name:      name,
		ParentID:  parentID,
	})
	if err == nil {
		if existingByName.NodeType != "scan_target" {
			return dbgen.AssetNode{}, errors.New("asset name conflicts with existing folder item")
		}
		if existingByName.TargetRef.Valid && existingByName.TargetRef.String != resolvedTargetRef {
			return dbgen.AssetNode{}, errors.New("asset name conflicts with existing target reference")
		}
		if !existingByName.TargetRef.Valid {
			if err := queries.UpdateAssetTargetRef(r.Context(), dbgen.UpdateAssetTargetRefParams{ID: existingByName.ID, TargetRef: sql.NullString{String: resolvedTargetRef, Valid: true}, UpdatedAt: time.Now().UTC()}); err != nil {
				return dbgen.AssetNode{}, err
			}
			existingByName.TargetRef = sql.NullString{String: resolvedTargetRef, Valid: true}
		}
		return existingByName, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return dbgen.AssetNode{}, err
	}

	now := time.Now().UTC()
	return queries.CreateAssetNode(r.Context(), dbgen.CreateAssetNodeParams{
		ID:           uuid.NewString(),
		ProjectID:    projectID,
		ParentID:     parentID,
		NodeType:     "scan_target",
		Name:         name,
		Path:         childPath(parentPath, name),
		TargetRef:    sql.NullString{String: resolvedTargetRef, Valid: true},
		MetadataJson: mustJSON(map[string]any{"source": "import_upload", "scanner": trivyScanner, "report_kind": trivyReportKind}),
		SortOrder:    0,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}

type trivyPersistResult struct {
	attempt dbgen.ImportAttempt
	scan    dbgen.Scan
}

func persistTrivyImport(r *http.Request, deps Dependencies, projectID string, scanTargetID string, actor identity.AuthenticatedActor, report parsedTrivyReport, startedAt *time.Time) (trivyPersistResult, error) {
	queries := dbgen.New(deps.DB)
	now := time.Now().UTC()
	metadata := mustJSON(map[string]any{"scanner": trivyScanner, "finding_count": len(report.Findings), "raw_report_retained": false})
	attempt, err := queries.CreateImportAttempt(r.Context(), dbgen.CreateImportAttemptParams{
		ID:                    uuid.NewString(),
		ProjectID:             projectID,
		AssetNodeID:           sql.NullString{String: scanTargetID, Valid: true},
		UploaderPrincipalType: sql.NullString{String: actor.PrincipalType, Valid: true},
		UploaderPrincipalID:   sql.NullString{String: actor.PrincipalID, Valid: true},
		Status:                "success",
		ParserName:            trivyReportKind,
		SanitizedMessage:      sql.NullString{String: "import completed", Valid: true},
		CorrelationID:         sql.NullString{},
		MetadataJson:          metadata,
		CreatedAt:             now,
		UpdatedAt:             now,
	})
	if err != nil {
		return trivyPersistResult{}, err
	}
	scan, err := queries.CreateScan(r.Context(), dbgen.CreateScanParams{
		ID:            uuid.NewString(),
		ProjectID:     projectID,
		ScanTargetID:  scanTargetID,
		ScannerKind:   trivyScanner,
		ReportKind:    trivyReportKind,
		ParserVersion: trivyParserVersion,
		ScanStartedAt: nullTimeFromPtr(startedAt),
		MetadataJson:  mustJSON(map[string]any{"target": report.Target}),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		return trivyPersistResult{}, err
	}
	for _, finding := range report.Findings {
		additional := []string{}
		for _, identifier := range finding.Identifiers {
			if identifier != finding.PrimaryIdentifier {
				additional = append(additional, identifier)
			}
		}
		groupStatus := "open"
		if _, err := queries.CreateProjectVulnerabilityGroup(r.Context(), dbgen.CreateProjectVulnerabilityGroupParams{
			ID:                        uuid.NewString(),
			ProjectID:                 projectID,
			PrimaryIdentifier:         finding.PrimaryIdentifier,
			AdditionalIdentifiersJson: mustJSON(additional),
			FirstDetectedAt:           now,
			Severity:                  finding.Severity,
			Status:                    groupStatus,
			DedupeKey:                 finding.PrimaryIdentifier,
			CreatedAt:                 now,
			UpdatedAt:                 now,
		}); err != nil {
			return trivyPersistResult{}, err
		}
		rawFinding, err := queries.CreateRawFindingInstance(r.Context(), dbgen.CreateRawFindingInstanceParams{
			ID:                  uuid.NewString(),
			ProjectID:           projectID,
			ScanID:              scan.ID,
			ScanTargetID:        scanTargetID,
			ScannerKind:         trivyScanner,
			ScannerFindingID:    finding.ScannerFindingID,
			DedupeKey:           finding.DedupeKey,
			IdentifiersJson:     mustJSON(finding.Identifiers),
			PrimaryIdentifier:   finding.PrimaryIdentifier,
			Severity:            finding.Severity,
			CvssJson:            mustJSON(finding.CVSS),
			PackageName:         nullStringFromPtr(finding.PackageName),
			PackageVersion:      nullStringFromPtr(finding.PackageVersion),
			FixedVersion:        nullStringFromPtr(finding.FixedVersion),
			ArtifactName:        nullStringFromPtr(finding.ArtifactName),
			ArtifactType:        nullStringFromPtr(finding.ArtifactType),
			ArtifactPath:        nullStringFromPtr(finding.ArtifactPath),
			FirstSeenAt:         now,
			LastSeenAt:          now,
			PresentInLatestScan: true,
			Status:              "open",
			ReferencesJson:      mustJSON(finding.References),
			SourceJson:          mustJSON(finding.Source),
			CreatedAt:           now,
			UpdatedAt:           now,
		})
		if err != nil {
			return trivyPersistResult{}, err
		}
		inheritedStatus, err := applyImportedReleaseInheritance(r, queries, projectID, scanTargetID, scan.ReportKind, rawFinding, now)
		if err != nil {
			return trivyPersistResult{}, err
		}
		if inheritedStatus != "" {
			groupStatus = inheritedStatus
			if err := queries.UpdateProjectVulnerabilityGroupStatus(r.Context(), dbgen.UpdateProjectVulnerabilityGroupStatusParams{
				Status:    groupStatus,
				UpdatedAt: now,
				ProjectID: projectID,
				DedupeKey: finding.PrimaryIdentifier,
			}); err != nil {
				return trivyPersistResult{}, err
			}
		}
	}
	return trivyPersistResult{attempt: attempt, scan: scan}, nil
}

func applyImportedReleaseInheritance(r *http.Request, queries *dbgen.Queries, projectID string, scanTargetID string, reportKind string, finding dbgen.RawFindingInstance, now time.Time) (string, error) {
	if finding.Status != "open" {
		return "", nil
	}
	decision, context, err := latestApplicableReleaseDecision(r, queries, projectID, scanTargetID, finding.ScannerKind, reportKind, finding.PrimaryIdentifier, optionalStringValue(finding.PackageName))
	if err != nil || decision == nil {
		return "", err
	}
	if decision.Status == "open" {
		return "open", nil
	}
	if _, err := queries.UpdateRawFindingStatus(r.Context(), dbgen.UpdateRawFindingStatusParams{
		Status:    decision.Status,
		UpdatedAt: now,
		ID:        finding.ID,
	}); err != nil {
		return "", err
	}
	body := "Inherited " + decision.Status + " from " + context.ScopePath + "/" + decision.ReleaseVersion + "."
	if _, err := queries.CreateFindingComment(r.Context(), dbgen.CreateFindingCommentParams{
		ID:                  uuid.NewString(),
		FindingID:           finding.ID,
		ProjectID:           projectID,
		AuthorPrincipalType: "machine",
		AuthorPrincipalID:   "system",
		Body:                body,
		IsSystem:            true,
		StatusFrom:          sql.NullString{String: "open", Valid: true},
		StatusTo:            sql.NullString{String: decision.Status, Valid: true},
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		return "", err
	}
	return decision.Status, nil
}

func createFailedImportAttempt(w http.ResponseWriter, r *http.Request, deps Dependencies, projectID string, scanTargetID string, actor identity.AuthenticatedActor, message string) *dbgen.ImportAttempt {
	now := time.Now().UTC()
	attempt, err := dbgen.New(deps.DB).CreateImportAttempt(r.Context(), dbgen.CreateImportAttemptParams{
		ID:                    uuid.NewString(),
		ProjectID:             projectID,
		AssetNodeID:           sql.NullString{String: scanTargetID, Valid: scanTargetID != ""},
		UploaderPrincipalType: sql.NullString{String: actor.PrincipalType, Valid: true},
		UploaderPrincipalID:   sql.NullString{String: actor.PrincipalID, Valid: true},
		Status:                "failed",
		ParserName:            trivyReportKind,
		SanitizedMessage:      sql.NullString{String: message, Valid: true},
		CorrelationID:         sql.NullString{},
		MetadataJson:          mustJSON(map[string]any{"failure_category": "parser_error", "raw_report_retained": false}),
		CreatedAt:             now,
		UpdatedAt:             now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return &attempt
}

func readTrivyUpload(w http.ResponseWriter, r *http.Request, settings config.Settings) ([]byte, string, bool) {
	maxBytes := int64(settings.MaxReportUploadBytes)
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart upload")
		return nil, "", false
	}
	projectID := strings.TrimSpace(r.FormValue("project_id"))
	file, _, err := r.FormFile("report_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "report_file is required")
		return nil, "", false
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Unable to read report_file")
		return nil, "", false
	}
	if int64(len(payload)) > maxBytes {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return nil, "", false
	}
	return payload, projectID, true
}

func parseTrivyImageJSON(payload []byte) (parsedTrivyReport, error) {
	var raw map[string]any
	decoder := json.NewDecoder(bytesReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return parsedTrivyReport{}, errors.New("invalid JSON: unable to parse Trivy report")
	}
	artifactName := stringValue(raw["ArtifactName"])
	startedAt := parseTrivyTime(stringValue(raw["CreatedAt"]))
	results, _ := raw["Results"].([]any)
	byKey := map[string]parsedFinding{}
	for _, resultRaw := range results {
		result, ok := resultRaw.(map[string]any)
		if !ok {
			continue
		}
		target := stringPtrOrNil(stringValue(result["Target"]))
		resultType := stringPtrOrNil(stringValue(result["Type"]))
		resultClass := stringPtrOrNil(stringValue(result["Class"]))
		vulns, _ := result["Vulnerabilities"].([]any)
		for _, vulnRaw := range vulns {
			vuln, ok := vulnRaw.(map[string]any)
			if !ok {
				continue
			}
			finding := parsedFindingFromVulnerability(vuln, artifactName, target, resultType, resultClass)
			existing, exists := byKey[finding.DedupeKey]
			if exists {
				byKey[finding.DedupeKey] = mergeParsedFindings(existing, finding)
				continue
			}
			byKey[finding.DedupeKey] = finding
		}
	}
	findings := make([]parsedFinding, 0, len(byKey))
	for _, finding := range byKey {
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].PrimaryIdentifier < findings[j].PrimaryIdentifier })
	return parsedTrivyReport{Target: artifactName, ScanStartedAt: startedAt, Findings: findings}, nil
}

func parsedFindingFromVulnerability(vuln map[string]any, artifactName string, artifactPath *string, artifactType *string, resultClass *string) parsedFinding {
	vulnID := stringValue(vuln["VulnerabilityID"])
	if vulnID == "" {
		vulnID = "UNKNOWN"
	}
	identifiers := uniqueStrings(append(stringSlice(vuln["CveIDs"]), vulnID))
	identifiers = uniqueStrings(append(identifiers, stringSlice(vuln["CweIDs"])...))
	identifiers = uniqueStrings(append(identifiers, stringSlice(vuln["VendorIDs"])...))
	primary := vulnID
	for _, identifier := range identifiers {
		if strings.HasPrefix(strings.ToUpper(identifier), "CVE-") {
			primary = identifier
			break
		}
	}
	identifiers = uniqueStrings(append([]string{primary}, identifiers...))
	packageName := stringPtrOrNil(stringValue(vuln["PkgName"]))
	packageVersion := stringPtrOrNil(stringValue(vuln["InstalledVersion"]))
	fixedVersion := stringPtrOrNil(stringValue(vuln["FixedVersion"]))
	dedupeKey := strings.Join([]string{trivyScanner, valueOrEmpty(artifactPath), valueOrEmpty(packageName), valueOrEmpty(packageVersion), valueOrEmpty(fixedVersion), primary}, "|")
	scannerFindingID := primary
	if packageName != nil && packageVersion != nil {
		scannerFindingID = primary + ":" + *packageName + ":" + *packageVersion
	}
	source := map[string]any{
		"scanner":          trivyScanner,
		"vulnerability_id": vulnID,
		"package_id":       stringPtrOrNil(stringValue(vuln["PkgID"])),
		"result_target":    artifactPath,
		"result_class":     resultClass,
		"result_type":      artifactType,
		"title":            stringPtrOrNil(stringValue(vuln["Title"])),
		"description":      stringPtrOrNil(stringValue(vuln["Description"])),
	}
	return parsedFinding{
		ScannerFindingID:  scannerFindingID,
		PrimaryIdentifier: primary,
		Identifiers:       identifiers,
		Severity:          normalizeSeverity(stringValue(vuln["Severity"])),
		PackageName:       packageName,
		PackageVersion:    packageVersion,
		FixedVersion:      fixedVersion,
		PackagePath:       stringPtrOrNil(stringValue(vuln["PkgPath"])),
		ArtifactName:      stringPtrOrNil(artifactName),
		ArtifactType:      artifactType,
		ArtifactPath:      artifactPath,
		DedupeKey:         dedupeKey,
		References:        stringSlice(vuln["References"]),
		CVSS:              cvssValue(vuln["CVSS"]),
		Source:            source,
	}
}

func mergeParsedFindings(preferred parsedFinding, secondary parsedFinding) parsedFinding {
	preferred.Identifiers = uniqueStrings(append(preferred.Identifiers, secondary.Identifiers...))
	if severityRank(secondary.Severity) > severityRank(preferred.Severity) {
		preferred.Severity = secondary.Severity
	}
	preferred.CVSS = mergeCVSS(preferred.CVSS, secondary.CVSS)
	preferred.References = uniqueStrings(append(preferred.References, secondary.References...))
	preferred.Source = mergeSource(preferred.Source, secondary.Source)
	return preferred
}

func mergeCVSS(existing map[string]any, duplicate map[string]any) map[string]any {
	merged := map[string]any{}
	for source, value := range existing {
		if typed, ok := value.(map[string]any); ok {
			copied := map[string]any{}
			for key, nested := range typed {
				copied[key] = nested
			}
			merged[source] = copied
			continue
		}
		merged[source] = value
	}
	for source, value := range duplicate {
		duplicateValues, ok := value.(map[string]any)
		if !ok {
			continue
		}
		current, ok := merged[source].(map[string]any)
		if !ok {
			current = map[string]any{}
			merged[source] = current
		}
		for key, nested := range duplicateValues {
			current[key] = nested
		}
	}
	return merged
}

func mergeSource(existing map[string]any, duplicate map[string]any) map[string]any {
	duplicateCount := 1
	if raw, ok := existing["duplicate_count"].(int); ok {
		duplicateCount = raw
	}
	merged := map[string]any{}
	for key, value := range existing {
		merged[key] = value
	}
	merged["duplicate_count"] = duplicateCount + 1
	merged["duplicate_vulnerability_ids"] = uniqueStrings([]string{stringValue(existing["vulnerability_id"]), stringValue(duplicate["vulnerability_id"])})
	return merged
}

func previewResponseFromReport(report parsedTrivyReport) trivyPreviewResponse {
	projectName, assetName, targetRef := trivyTargetDefaults(report.Target)
	return trivyPreviewResponse{
		Scanner:             trivyScanner,
		ReportKind:          trivyReportKind,
		ToolLabel:           "Trivy (Image)",
		DetectedProjectName: projectName,
		DetectedAssetName:   assetName,
		DetectedTargetRef:   targetRef,
		ScanStartedAt:       report.ScanStartedAt,
		FindingCount:        len(report.Findings),
		GroupCount:          groupCount(report),
	}
}

func trivyTargetDefaults(target string) (string, string, string) {
	leaf := target
	if slash := strings.LastIndex(leaf, "/"); slash >= 0 {
		leaf = leaf[slash+1:]
	}
	imageName := leaf
	tag := leaf
	nameAndTag, _, hasDigest := strings.Cut(leaf, "@")
	if colon := strings.LastIndex(nameAndTag, ":"); colon > 0 {
		imageName = nameAndTag[:colon]
		tag = nameAndTag[colon+1:]
	} else if hasDigest {
		imageName = nameAndTag
	}
	return strings.TrimSpace(imageName), strings.TrimSpace(tag), strings.TrimSpace(target)
}

func groupCount(report parsedTrivyReport) int {
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		seen[finding.PrimaryIdentifier] = true
	}
	return len(seen)
}

func parseOptionalScanTime(w http.ResponseWriter, raw string) (*time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	parsed := parseTrivyTime(raw)
	if parsed == nil {
		writeError(w, http.StatusBadRequest, "scan_started_at must be an ISO-8601 datetime")
		return nil, false
	}
	return parsed, true
}

func parseTrivyTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		utc := parsed.UTC()
		return &utc
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			utc := parsed.UTC()
			return &utc
		}
	}
	return nil
}

func nullTimeFromPtr(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func stringPtrOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := []string{}
	for _, item := range raw {
		if text, ok := item.(string); ok && text != "" {
			values = append(values, text)
		}
	}
	return values
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	unique := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

func normalizeSeverity(value string) string {
	value = strings.ToUpper(value)
	if value == "" {
		return "UNKNOWN"
	}
	return value
}

func severityRank(value string) int {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func mustJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(payload)
}

func bytesReader(payload []byte) *strings.Reader {
	return strings.NewReader(string(payload))
}

func cvssValue(value any) map[string]any {
	raw, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	normalized := map[string]any{}
	for source, sourceValue := range raw {
		sourceCVSS, ok := sourceValue.(map[string]any)
		if !ok {
			continue
		}
		sourceValues := map[string]any{}
		if version := cvssVersion(sourceCVSS, "V2"); len(version) > 0 {
			sourceValues["v2"] = version
		}
		if version := cvssVersion(sourceCVSS, "V3"); len(version) > 0 {
			sourceValues["v3"] = version
		}
		if len(sourceValues) > 0 {
			normalized[source] = sourceValues
		}
	}
	return normalized
}

func cvssVersion(sourceCVSS map[string]any, prefix string) map[string]any {
	version := map[string]any{}
	switch score := sourceCVSS[prefix+"Score"].(type) {
	case float64:
		version["score"] = score
	case int:
		version["score"] = score
	case json.Number:
		if parsed, err := score.Float64(); err == nil {
			version["score"] = parsed
		}
	}
	if vector := stringValue(sourceCVSS[prefix+"Vector"]); vector != "" {
		version["vector"] = vector
	}
	return version
}

func importHistoryLimit(r *http.Request) int64 {
	limit := int64(50)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func adminImportAttemptResponseFromDB(row dbgen.ListAdminImportAttemptsRow) (adminImportAttemptResponse, error) {
	metadata := map[string]any{}
	if row.MetadataJson != "" {
		if err := json.Unmarshal([]byte(row.MetadataJson), &metadata); err != nil {
			return adminImportAttemptResponse{}, err
		}
	}
	return adminImportAttemptResponse{
		ID:                    row.ID,
		ProjectID:             row.ProjectID,
		ProjectName:           row.ProjectName,
		AssetID:               optionalStringFromNull(row.AssetNodeID),
		AssetName:             optionalStringFromNull(row.AssetName),
		AssetPath:             optionalStringFromNull(row.AssetPath),
		UploaderPrincipalType: optionalStringFromNull(row.UploaderPrincipalType),
		UploaderPrincipalID:   optionalStringFromNull(row.UploaderPrincipalID),
		UploaderDisplay:       importUploaderDisplay(row),
		Status:                row.Status,
		ParserName:            row.ParserName,
		SanitizedMessage:      optionalStringFromNull(row.SanitizedMessage),
		CorrelationID:         optionalStringFromNull(row.CorrelationID),
		Metadata:              sanitizeImportMetadata(metadata),
		CreatedAt:             row.CreatedAt.UTC(),
		UpdatedAt:             row.UpdatedAt.UTC(),
	}, nil
}

func importUploaderDisplay(row dbgen.ListAdminImportAttemptsRow) *string {
	if row.UserDisplay.Valid {
		return &row.UserDisplay.String
	}
	if row.MachineDisplay.Valid {
		return &row.MachineDisplay.String
	}
	return nil
}

func sanitizeImportMetadata(metadata map[string]any) map[string]any {
	allowed := map[string]bool{
		"failure_category":    true,
		"finding_count":       true,
		"raw_report_retained": true,
		"scanner":             true,
		"scanner_guess":       true,
	}
	sanitized := map[string]any{}
	for key, value := range metadata {
		if allowed[key] {
			sanitized[key] = value
		}
	}
	return sanitized
}
