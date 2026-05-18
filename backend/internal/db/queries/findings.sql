-- name: ListFindingRows :many
SELECT
    raw_finding_instances.id AS finding_id,
    raw_finding_instances.project_id,
    projects.name AS project_name,
    raw_finding_instances.scan_target_id,
    asset_nodes.name AS scan_target_name,
    asset_nodes.path AS scan_target_path,
    asset_nodes.target_ref AS scan_target_ref,
    raw_finding_instances.scanner_kind,
    scans.report_kind,
    raw_finding_instances.scanner_finding_id,
    raw_finding_instances.dedupe_key,
    raw_finding_instances.identifiers_json,
    raw_finding_instances.primary_identifier,
    raw_finding_instances.severity,
    raw_finding_instances.cvss_json,
    raw_finding_instances.package_name,
    raw_finding_instances.package_version,
    raw_finding_instances.fixed_version,
    raw_finding_instances.artifact_name,
    raw_finding_instances.artifact_type,
    raw_finding_instances.artifact_path,
    raw_finding_instances.first_seen_at,
    raw_finding_instances.last_seen_at,
    raw_finding_instances.present_in_latest_scan,
    raw_finding_instances.status,
    raw_finding_instances.references_json,
    raw_finding_instances.source_json,
    projects.sla_tracking_enabled,
    projects.sla_reporting_enabled,
    projects.grace_period_enabled,
    projects.grace_period_percent,
    projects.critical_sla_days,
    projects.high_sla_days,
    projects.medium_sla_days,
    projects.low_sla_days,
    projects.unknown_sla_days,
    asset_nodes.sla_tracking_enabled AS asset_sla_tracking_enabled,
    asset_nodes.sla_reporting_enabled AS asset_sla_reporting_enabled,
    asset_nodes.grace_period_enabled AS asset_grace_period_enabled,
    asset_nodes.grace_period_percent AS asset_grace_period_percent,
    project_vulnerability_groups.id AS group_id,
    project_vulnerability_groups.primary_identifier AS group_primary_identifier,
    project_vulnerability_groups.additional_identifiers_json AS group_additional_identifiers_json,
    project_vulnerability_groups.first_detected_at AS group_first_detected_at,
    project_vulnerability_groups.status AS group_status
FROM raw_finding_instances
JOIN scans ON scans.id = raw_finding_instances.scan_id
JOIN projects ON projects.id = raw_finding_instances.project_id
JOIN asset_nodes ON asset_nodes.id = raw_finding_instances.scan_target_id
LEFT JOIN project_vulnerability_groups ON
    project_vulnerability_groups.project_id = raw_finding_instances.project_id
    AND project_vulnerability_groups.dedupe_key = raw_finding_instances.primary_identifier
ORDER BY raw_finding_instances.last_seen_at DESC, raw_finding_instances.primary_identifier, raw_finding_instances.id;

-- name: GetFindingRow :one
SELECT
    raw_finding_instances.id AS finding_id,
    raw_finding_instances.project_id,
    projects.name AS project_name,
    raw_finding_instances.scan_target_id,
    asset_nodes.name AS scan_target_name,
    asset_nodes.path AS scan_target_path,
    asset_nodes.target_ref AS scan_target_ref,
    raw_finding_instances.scanner_kind,
    scans.report_kind,
    raw_finding_instances.scanner_finding_id,
    raw_finding_instances.dedupe_key,
    raw_finding_instances.identifiers_json,
    raw_finding_instances.primary_identifier,
    raw_finding_instances.severity,
    raw_finding_instances.cvss_json,
    raw_finding_instances.package_name,
    raw_finding_instances.package_version,
    raw_finding_instances.fixed_version,
    raw_finding_instances.artifact_name,
    raw_finding_instances.artifact_type,
    raw_finding_instances.artifact_path,
    raw_finding_instances.first_seen_at,
    raw_finding_instances.last_seen_at,
    raw_finding_instances.present_in_latest_scan,
    raw_finding_instances.status,
    raw_finding_instances.references_json,
    raw_finding_instances.source_json,
    projects.sla_tracking_enabled,
    projects.sla_reporting_enabled,
    projects.grace_period_enabled,
    projects.grace_period_percent,
    projects.critical_sla_days,
    projects.high_sla_days,
    projects.medium_sla_days,
    projects.low_sla_days,
    projects.unknown_sla_days,
    asset_nodes.sla_tracking_enabled AS asset_sla_tracking_enabled,
    asset_nodes.sla_reporting_enabled AS asset_sla_reporting_enabled,
    asset_nodes.grace_period_enabled AS asset_grace_period_enabled,
    asset_nodes.grace_period_percent AS asset_grace_period_percent,
    project_vulnerability_groups.id AS group_id,
    project_vulnerability_groups.primary_identifier AS group_primary_identifier,
    project_vulnerability_groups.additional_identifiers_json AS group_additional_identifiers_json,
    project_vulnerability_groups.first_detected_at AS group_first_detected_at,
    project_vulnerability_groups.status AS group_status
FROM raw_finding_instances
JOIN scans ON scans.id = raw_finding_instances.scan_id
JOIN projects ON projects.id = raw_finding_instances.project_id
JOIN asset_nodes ON asset_nodes.id = raw_finding_instances.scan_target_id
LEFT JOIN project_vulnerability_groups ON
    project_vulnerability_groups.project_id = raw_finding_instances.project_id
    AND project_vulnerability_groups.dedupe_key = raw_finding_instances.primary_identifier
WHERE raw_finding_instances.id = $1;

-- name: CreateFindingComment :one
INSERT INTO finding_comments (
    id,
    finding_id,
    project_id,
    author_principal_type,
    author_principal_id,
    body,
    is_system,
    status_from,
    status_to,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING
    id,
    finding_id,
    project_id,
    author_principal_type,
    author_principal_id,
    body,
    is_system,
    status_from,
    status_to,
    created_at,
    updated_at;

-- name: CreateFindingStatusChangeRequest :one
INSERT INTO finding_status_change_requests (
    id,
    finding_id,
    project_id,
    requester_principal_type,
    requester_principal_id,
    reviewer_principal_type,
    reviewer_principal_id,
    from_status,
    to_status,
    state,
    comment,
    decision_comment,
    decided_at,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING
    id,
    finding_id,
    project_id,
    requester_principal_type,
    requester_principal_id,
    reviewer_principal_type,
    reviewer_principal_id,
    from_status,
    to_status,
    state,
    comment,
    decision_comment,
    decided_at,
    created_at,
    updated_at;

-- name: GetFindingStatusChangeRequest :one
SELECT
    id,
    finding_id,
    project_id,
    requester_principal_type,
    requester_principal_id,
    reviewer_principal_type,
    reviewer_principal_id,
    from_status,
    to_status,
    state,
    comment,
    decision_comment,
    decided_at,
    created_at,
    updated_at
FROM finding_status_change_requests
WHERE id = $1 AND finding_id = $2;

-- name: UpdateFindingStatusChangeRequestDecision :one
UPDATE finding_status_change_requests
SET
    state = $1,
    reviewer_principal_type = $2,
    reviewer_principal_id = $3,
    decision_comment = $4,
    decided_at = $5,
    updated_at = $6
WHERE id = $7
RETURNING
    id,
    finding_id,
    project_id,
    requester_principal_type,
    requester_principal_id,
    reviewer_principal_type,
    reviewer_principal_id,
    from_status,
    to_status,
    state,
    comment,
    decision_comment,
    decided_at,
    created_at,
    updated_at;

-- name: UpdateRawFindingStatus :one
UPDATE raw_finding_instances
SET status = $1, updated_at = $2
WHERE id = $3
RETURNING
    id,
    project_id,
    scan_id,
    scan_target_id,
    scanner_kind,
    scanner_finding_id,
    dedupe_key,
    identifiers_json,
    primary_identifier,
    severity,
    cvss_json,
    package_name,
    package_version,
    fixed_version,
    artifact_name,
    artifact_type,
    artifact_path,
    first_seen_at,
    last_seen_at,
    present_in_latest_scan,
    status,
    references_json,
    source_json,
    created_at,
    updated_at;

-- name: UpdateProjectVulnerabilityGroupStatus :exec
UPDATE project_vulnerability_groups
SET status = $1, updated_at = $2
WHERE project_id = $3 AND dedupe_key = $4;

-- name: UpsertFindingReleaseStatusDecision :one
INSERT INTO finding_release_status_decisions (
    id,
    project_id,
    release_scope_asset_id,
    release_version_asset_id,
    release_version,
    scanner_kind,
    report_kind,
    finding_identity,
    status,
    source_finding_id,
    source_comment_id,
    source_request_id,
    decided_at,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (
    project_id,
    release_scope_asset_id,
    release_version_asset_id,
    scanner_kind,
    report_kind,
    finding_identity
) DO UPDATE SET
    release_version = excluded.release_version,
    status = excluded.status,
    source_finding_id = excluded.source_finding_id,
    source_comment_id = excluded.source_comment_id,
    source_request_id = excluded.source_request_id,
    decided_at = excluded.decided_at,
    updated_at = excluded.updated_at
RETURNING
    id,
    project_id,
    release_scope_asset_id,
    release_version_asset_id,
    release_version,
    scanner_kind,
    report_kind,
    finding_identity,
    status,
    source_finding_id,
    source_comment_id,
    source_request_id,
    decided_at,
    created_at,
    updated_at;

-- name: ListReleaseStatusDecisions :many
SELECT
    id,
    project_id,
    release_scope_asset_id,
    release_version_asset_id,
    release_version,
    scanner_kind,
    report_kind,
    finding_identity,
    status,
    source_finding_id,
    source_comment_id,
    source_request_id,
    decided_at,
    created_at,
    updated_at
FROM finding_release_status_decisions
WHERE
    project_id = $1
    AND release_scope_asset_id = $2
    AND scanner_kind = $3
    AND report_kind = $4
    AND finding_identity = $5;

-- name: ListFindingComments :many
SELECT
    finding_comments.id,
    finding_comments.finding_id,
    finding_comments.project_id,
    finding_comments.author_principal_type,
    finding_comments.author_principal_id,
    users.display_name AS user_display,
    machine_credentials.name AS machine_display,
    finding_comments.body,
    finding_comments.is_system,
    finding_comments.status_from,
    finding_comments.status_to,
    finding_comments.created_at,
    finding_comments.updated_at
FROM finding_comments
LEFT JOIN users ON users.id = finding_comments.author_principal_id
    AND finding_comments.author_principal_type = 'user'
LEFT JOIN machine_credentials ON machine_credentials.id = finding_comments.author_principal_id
    AND finding_comments.author_principal_type = 'machine'
WHERE finding_comments.finding_id = $1
ORDER BY finding_comments.created_at, finding_comments.id;

-- name: ListFindingStatusChangeRequests :many
SELECT
    finding_status_change_requests.id,
    finding_status_change_requests.finding_id,
    finding_status_change_requests.project_id,
    finding_status_change_requests.requester_principal_type,
    finding_status_change_requests.requester_principal_id,
    requester_user.display_name AS requester_user_display,
    requester_machine.name AS requester_machine_display,
    finding_status_change_requests.reviewer_principal_type,
    finding_status_change_requests.reviewer_principal_id,
    reviewer_user.display_name AS reviewer_user_display,
    reviewer_machine.name AS reviewer_machine_display,
    finding_status_change_requests.from_status,
    finding_status_change_requests.to_status,
    finding_status_change_requests.state,
    finding_status_change_requests.comment,
    finding_status_change_requests.decision_comment,
    finding_status_change_requests.decided_at,
    finding_status_change_requests.created_at,
    finding_status_change_requests.updated_at
FROM finding_status_change_requests
LEFT JOIN users AS requester_user ON requester_user.id = finding_status_change_requests.requester_principal_id
    AND finding_status_change_requests.requester_principal_type = 'user'
LEFT JOIN machine_credentials AS requester_machine ON requester_machine.id = finding_status_change_requests.requester_principal_id
    AND finding_status_change_requests.requester_principal_type = 'machine'
LEFT JOIN users AS reviewer_user ON reviewer_user.id = finding_status_change_requests.reviewer_principal_id
    AND finding_status_change_requests.reviewer_principal_type = 'user'
LEFT JOIN machine_credentials AS reviewer_machine ON reviewer_machine.id = finding_status_change_requests.reviewer_principal_id
    AND finding_status_change_requests.reviewer_principal_type = 'machine'
WHERE finding_status_change_requests.finding_id = $1
ORDER BY finding_status_change_requests.created_at, finding_status_change_requests.id;
