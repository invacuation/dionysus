package httpapi_test

import "time"

const (
	bearerAuthScheme  = "bearer"
	sessionCookieName = "dionysus_session"
)

type actorResponse struct {
	ActorType               string                    `json:"actor_type"`
	ActorID                 string                    `json:"actor_id"`
	DisplayName             string                    `json:"display_name"`
	PrincipalType           string                    `json:"principal_type"`
	PrincipalID             string                    `json:"principal_id"`
	AuthMethod              string                    `json:"auth_method"`
	SessionID               *string                   `json:"session_id"`
	MachineTokenID          *string                   `json:"machine_token_id"`
	MixedCredentialsPresent bool                      `json:"mixed_credentials_present"`
	BearerTokenPresent      bool                      `json:"bearer_token_present"`
	SessionCookiePresent    bool                      `json:"session_cookie_present"`
	LocalAuthEnabled        bool                      `json:"local_auth_enabled"`
	Capabilities            actorCapabilitiesResponse `json:"capabilities"`
}

type actorCapabilitiesResponse struct {
	Navigation actorNavigationCapabilitiesResponse `json:"navigation"`
	Admin      actorAdminCapabilitiesResponse      `json:"admin"`
}

type actorNavigationCapabilitiesResponse struct {
	Overview  bool `json:"overview"`
	Findings  bool `json:"findings"`
	Inventory bool `json:"inventory"`
	Imports   bool `json:"imports"`
	Admin     bool `json:"admin"`
}

type actorAdminCapabilitiesResponse struct {
	Access             bool `json:"access"`
	AuditLog           bool `json:"audit_log"`
	ImportHistory      bool `json:"import_history"`
	MachineCredentials bool `json:"machine_credentials"`
	PermissionTester   bool `json:"permission_tester"`
	Sessions           bool `json:"sessions"`
	SecuritySettings   bool `json:"security_settings"`
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

type auditLogResponse struct {
	EventTypes []string                `json:"event_types"`
	Events     []auditLogEventResponse `json:"events"`
}

type auditLogEventResponse struct {
	ID                 string         `json:"id"`
	EventType          string         `json:"event_type"`
	ActorPrincipalType *string        `json:"actor_principal_type"`
	ActorPrincipalID   *string        `json:"actor_principal_id"`
	ActorDisplay       *string        `json:"actor_display"`
	TargetType         *string        `json:"target_type"`
	TargetID           *string        `json:"target_id"`
	ProjectID          *string        `json:"project_id"`
	IPAddress          *string        `json:"ip_address"`
	UserAgent          *string        `json:"user_agent"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          time.Time      `json:"created_at"`
}

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

type overviewResponse struct {
	OpenFindings        int                          `json:"open_findings"`
	OverdueSLA          int                          `json:"overdue_sla"`
	GracePeriodRisk     int                          `json:"grace_period_risk"`
	SeverityCounts      []overviewSeverityCount      `json:"severity_counts"`
	HighestRiskProjects []overviewProjectRiskSummary `json:"highest_risk_projects"`
}

type overviewSeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type overviewProjectRiskSummary struct {
	ProjectID    string `json:"project_id"`
	ProjectName  string `json:"project_name"`
	OpenCount    int    `json:"open_count"`
	OverdueCount int    `json:"overdue_count"`
}

type accessListResponse struct {
	Users                 []accessUserResponse                 `json:"users"`
	MachineCredentials    []accessMachineCredentialResponse    `json:"machine_credentials"`
	Groups                []accessGroupResponse                `json:"groups"`
	Memberships           []accessMembershipResponse           `json:"memberships"`
	PermissionAssignments []accessPermissionAssignmentResponse `json:"permission_assignments"`
	AvailablePermissions  []string                             `json:"available_permissions"`
}

type accessUserResponse struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accessMachineCredentialResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	ClientID  string     `json:"client_id"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type accessGroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	IsProtected bool      `json:"is_protected"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accessMembershipResponse struct {
	ID            string    `json:"id"`
	GroupID       string    `json:"group_id"`
	PrincipalType string    `json:"principal_type"`
	PrincipalID   string    `json:"principal_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type accessPermissionAssignmentResponse struct {
	ID            string    `json:"id"`
	PrincipalType string    `json:"principal_type"`
	PrincipalID   string    `json:"principal_id"`
	Permission    string    `json:"permission"`
	Effect        string    `json:"effect"`
	ScopeType     *string   `json:"scope_type"`
	ScopeID       *string   `json:"scope_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type machineCredentialResponse struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	ClientID               string     `json:"client_id"`
	IsActive               bool       `json:"is_active"`
	CreatedByPrincipalType *string    `json:"created_by_principal_type"`
	CreatedByPrincipalID   *string    `json:"created_by_principal_id"`
	CreatedByDisplay       *string    `json:"created_by_display"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

type machineCredentialWithSecretResponse struct {
	machineCredentialResponse
	ClientSecret string `json:"client_secret"`
}

type machineCredentialListResponse struct {
	Credentials []machineCredentialResponse `json:"credentials"`
}

type adminSessionListResponse struct {
	Sessions []adminSessionResponse `json:"sessions"`
}

type adminSessionResponse struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Username      string     `json:"username"`
	DisplayName   string     `json:"display_name"`
	IPAddress     *string    `json:"ip_address"`
	UserAgent     *string    `json:"user_agent"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	IdleExpiresAt time.Time  `json:"idle_expires_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	Active        bool       `json:"active"`
}

type permissionTestResponse struct {
	Allowed     bool   `json:"allowed"`
	Explanation string `json:"explanation"`
}

type securitySettingsResponse struct {
	ForcePeerReviewForStatusChanges bool `json:"force_peer_review_for_status_changes"`
	SessionIdleTimeoutMinutes       int  `json:"session_idle_timeout_minutes"`
	SessionAbsoluteTimeoutMinutes   int  `json:"session_absolute_timeout_minutes"`
}

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

type findingListResponse struct {
	Rows []findingRowResponse `json:"rows"`
}

type findingRowResponse struct {
	ID                    string         `json:"id"`
	ProjectID             string         `json:"project_id"`
	ProjectName           string         `json:"project_name"`
	ScanTargetID          string         `json:"scan_target_id"`
	ScanTargetName        string         `json:"scan_target_name"`
	ScanTargetPath        string         `json:"scan_target_path"`
	ScanTargetRef         *string        `json:"scan_target_ref"`
	Scanner               string         `json:"scanner"`
	PrimaryIdentifier     string         `json:"primary_identifier"`
	AdditionalIdentifiers []string       `json:"additional_identifiers"`
	PackageName           *string        `json:"package_name"`
	InstalledVersion      *string        `json:"installed_version"`
	FixedVersion          *string        `json:"fixed_version"`
	Severity              string         `json:"severity"`
	CVSS                  map[string]any `json:"cvss"`
	Status                string         `json:"status"`
	FirstDetectedAt       time.Time      `json:"first_detected_at"`
	LastSeenAt            time.Time      `json:"last_seen_at"`
	PresentInLatestScan   bool           `json:"present_in_latest_scan"`
	SLAActive             bool           `json:"sla_active"`
	SLARemainingDays      *int           `json:"sla_remaining_days"`
	GraceRemainingDays    *int           `json:"grace_remaining_days"`
	SLAStatus             string         `json:"sla_status"`
	SLAReason             *string        `json:"sla_reason"`
	SLADays               *int           `json:"sla_days"`
	GraceDays             *int           `json:"grace_days"`
	IncludeInSLAReports   bool           `json:"include_in_sla_reports"`
}

type findingDetailResponse struct {
	findingRowResponse
	ScannerFindingID     string                               `json:"scanner_finding_id"`
	DedupeKey            string                               `json:"dedupe_key"`
	Identifiers          []string                             `json:"identifiers"`
	References           []string                             `json:"references"`
	Description          *string                              `json:"description"`
	ArtifactName         *string                              `json:"artifact_name"`
	ArtifactType         *string                              `json:"artifact_type"`
	ArtifactPath         *string                              `json:"artifact_path"`
	SourceEvidence       map[string]any                       `json:"source_evidence"`
	ProjectGroup         *projectGroupResponse                `json:"project_group"`
	PeerReviewRequired   bool                                 `json:"peer_review_required_for_status_changes"`
	Comments             []findingCommentResponse             `json:"comments"`
	StatusChangeRequests []findingStatusChangeRequestResponse `json:"status_change_requests"`
}

type projectGroupResponse struct {
	ID                    string    `json:"id"`
	PrimaryIdentifier     string    `json:"primary_identifier"`
	AdditionalIdentifiers []string  `json:"additional_identifiers"`
	Status                string    `json:"status"`
	FirstDetectedAt       time.Time `json:"first_detected_at"`
}

type findingCommentResponse struct {
	ID                  string    `json:"id"`
	Body                string    `json:"body"`
	AuthorPrincipalType string    `json:"author_principal_type"`
	AuthorPrincipalID   string    `json:"author_principal_id"`
	AuthorDisplay       *string   `json:"author_display"`
	CreatedAt           time.Time `json:"created_at"`
	IsSystem            bool      `json:"is_system"`
	StatusFrom          *string   `json:"status_from"`
	StatusTo            *string   `json:"status_to"`
}

type findingStatusChangeRequestResponse struct {
	ID                     string     `json:"id"`
	RequesterPrincipalType string     `json:"requester_principal_type"`
	RequesterPrincipalID   string     `json:"requester_principal_id"`
	RequesterDisplay       *string    `json:"requester_display"`
	ReviewerPrincipalType  *string    `json:"reviewer_principal_type"`
	ReviewerPrincipalID    *string    `json:"reviewer_principal_id"`
	ReviewerDisplay        *string    `json:"reviewer_display"`
	FromStatus             string     `json:"from_status"`
	ToStatus               string     `json:"to_status"`
	State                  string     `json:"state"`
	Comment                *string    `json:"comment"`
	DecisionComment        *string    `json:"decision_comment"`
	CreatedAt              time.Time  `json:"created_at"`
	DecidedAt              *time.Time `json:"decided_at"`
}
