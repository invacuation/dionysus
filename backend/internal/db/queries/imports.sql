-- name: CreateImportAttempt :one
INSERT INTO import_attempts (
    id,
    project_id,
    asset_node_id,
    uploader_principal_type,
    uploader_principal_id,
    status,
    parser_name,
    sanitized_message,
    correlation_id,
    metadata_json,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING
    id,
    project_id,
    asset_node_id,
    uploader_principal_type,
    uploader_principal_id,
    status,
    parser_name,
    sanitized_message,
    correlation_id,
    metadata_json,
    created_at,
    updated_at;

-- name: CreateScan :one
INSERT INTO scans (
    id,
    project_id,
    scan_target_id,
    scanner_kind,
    report_kind,
    parser_version,
    scan_started_at,
    scan_finished_at,
    metadata_json,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING
    id,
    project_id,
    scan_target_id,
    scanner_kind,
    report_kind,
    parser_version,
    scan_started_at,
    scan_finished_at,
    metadata_json,
    created_at,
    updated_at;

-- name: CreateProjectVulnerabilityGroup :one
INSERT INTO project_vulnerability_groups (
    id,
    project_id,
    primary_identifier,
    additional_identifiers_json,
    first_detected_at,
    severity,
    status,
    dedupe_key,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (project_id, dedupe_key) DO UPDATE SET
    severity = excluded.severity,
    updated_at = excluded.updated_at
RETURNING
    id,
    project_id,
    primary_identifier,
    additional_identifiers_json,
    first_detected_at,
    severity,
    status,
    dedupe_key,
    created_at,
    updated_at;

-- name: CreateRawFindingInstance :one
INSERT INTO raw_finding_instances (
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
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_target_id, dedupe_key) DO UPDATE SET
    scan_id = excluded.scan_id,
    last_seen_at = excluded.last_seen_at,
    present_in_latest_scan = excluded.present_in_latest_scan,
    severity = excluded.severity,
    updated_at = excluded.updated_at
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

-- name: ListAdminImportAttempts :many
SELECT
    import_attempts.id,
    import_attempts.project_id,
    projects.name AS project_name,
    import_attempts.asset_node_id,
    asset_nodes.name AS asset_name,
    asset_nodes.path AS asset_path,
    import_attempts.uploader_principal_type,
    import_attempts.uploader_principal_id,
    users.display_name AS user_display,
    machine_credentials.name AS machine_display,
    import_attempts.status,
    import_attempts.parser_name,
    import_attempts.sanitized_message,
    import_attempts.correlation_id,
    import_attempts.metadata_json,
    import_attempts.created_at,
    import_attempts.updated_at
FROM import_attempts
JOIN projects ON projects.id = import_attempts.project_id
LEFT JOIN asset_nodes ON asset_nodes.id = import_attempts.asset_node_id
LEFT JOIN users ON users.id = import_attempts.uploader_principal_id
    AND import_attempts.uploader_principal_type = 'user'
LEFT JOIN machine_credentials ON machine_credentials.id = import_attempts.uploader_principal_id
    AND import_attempts.uploader_principal_type = 'machine'
ORDER BY import_attempts.created_at DESC
LIMIT ?;
