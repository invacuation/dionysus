CREATE TABLE app_security_settings (
    id VARCHAR(50) PRIMARY KEY NOT NULL,
    force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
    session_idle_timeout_minutes INTEGER,
    session_absolute_timeout_minutes INTEGER,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE audit_log_events (
    id VARCHAR PRIMARY KEY NOT NULL,
    event_type VARCHAR(120) NOT NULL,
    actor_principal_type VARCHAR(50),
    actor_principal_id VARCHAR(36),
    actor_display VARCHAR(255),
    target_type VARCHAR(120),
    target_id VARCHAR(255),
    project_id VARCHAR(36),
    ip_address VARCHAR(120),
    user_agent TEXT,
    metadata_json TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE groups (
    id VARCHAR PRIMARY KEY NOT NULL,
    name VARCHAR(150) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    is_protected BOOLEAN NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE group_memberships (
    id VARCHAR PRIMARY KEY NOT NULL,
    group_id VARCHAR NOT NULL,
    principal_type VARCHAR(20) NOT NULL,
    principal_id VARCHAR(36) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE machine_credentials (
    id VARCHAR PRIMARY KEY NOT NULL,
    name VARCHAR(150) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    client_secret_digest VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE machine_tokens (
    id VARCHAR PRIMARY KEY NOT NULL,
    machine_credential_id VARCHAR NOT NULL,
    token_digest VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (machine_credential_id) REFERENCES machine_credentials(id) ON DELETE CASCADE
);

CREATE TABLE machine_refresh_tokens (
    id VARCHAR PRIMARY KEY NOT NULL,
    machine_credential_id VARCHAR NOT NULL,
    token_digest VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (machine_credential_id) REFERENCES machine_credentials(id) ON DELETE CASCADE
);

CREATE TABLE permission_assignments (
    id VARCHAR PRIMARY KEY NOT NULL,
    principal_type VARCHAR(20) NOT NULL,
    principal_id VARCHAR(36) NOT NULL,
    permission VARCHAR(120) NOT NULL,
    effect VARCHAR(20) NOT NULL,
    scope_type VARCHAR(50),
    scope_id VARCHAR(36),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE projects (
    id VARCHAR PRIMARY KEY NOT NULL,
    slug VARCHAR(150) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    sla_tracking_enabled BOOLEAN NOT NULL,
    sla_reporting_enabled BOOLEAN NOT NULL,
    grace_period_enabled BOOLEAN NOT NULL,
    grace_period_percent INTEGER NOT NULL,
    require_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
    critical_sla_days INTEGER NOT NULL DEFAULT 30,
    high_sla_days INTEGER NOT NULL DEFAULT 60,
    medium_sla_days INTEGER NOT NULL DEFAULT 90,
    low_sla_days INTEGER NOT NULL DEFAULT 180,
    unknown_sla_days INTEGER NOT NULL DEFAULT 365,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE asset_nodes (
    id VARCHAR PRIMARY KEY NOT NULL,
    project_id VARCHAR NOT NULL,
    parent_id VARCHAR,
    node_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    target_ref TEXT,
    metadata_json TEXT NOT NULL,
    sla_tracking_enabled BOOLEAN,
    sla_reporting_enabled BOOLEAN,
    grace_period_enabled BOOLEAN,
    grace_period_percent INTEGER,
    sort_order INTEGER NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES asset_nodes(id) ON DELETE CASCADE,
    UNIQUE (project_id, path)
);

CREATE TABLE import_attempts (
    id VARCHAR PRIMARY KEY NOT NULL,
    project_id VARCHAR NOT NULL,
    asset_node_id VARCHAR,
    uploader_principal_type VARCHAR(50),
    uploader_principal_id VARCHAR(36),
    status VARCHAR(20) NOT NULL,
    parser_name VARCHAR(120) NOT NULL,
    sanitized_message TEXT,
    correlation_id VARCHAR(120),
    metadata_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_node_id) REFERENCES asset_nodes(id) ON DELETE CASCADE
);

CREATE TABLE scans (
    id VARCHAR PRIMARY KEY NOT NULL,
    project_id VARCHAR NOT NULL,
    scan_target_id VARCHAR NOT NULL,
    scanner_kind VARCHAR(50) NOT NULL,
    report_kind VARCHAR(120) NOT NULL,
    parser_version VARCHAR(50) NOT NULL,
    scan_started_at DATETIME,
    scan_finished_at DATETIME,
    metadata_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_target_id) REFERENCES asset_nodes(id) ON DELETE CASCADE
);

CREATE TABLE project_vulnerability_groups (
    id VARCHAR PRIMARY KEY NOT NULL,
    project_id VARCHAR NOT NULL,
    primary_identifier VARCHAR(255) NOT NULL,
    additional_identifiers_json TEXT NOT NULL,
    first_detected_at DATETIME NOT NULL,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    dedupe_key VARCHAR(512) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE (project_id, dedupe_key)
);

CREATE TABLE raw_finding_instances (
    id VARCHAR PRIMARY KEY NOT NULL,
    project_id VARCHAR NOT NULL,
    scan_id VARCHAR NOT NULL,
    scan_target_id VARCHAR NOT NULL,
    scanner_kind VARCHAR(50) NOT NULL,
    scanner_finding_id TEXT NOT NULL,
    dedupe_key VARCHAR(512) NOT NULL,
    identifiers_json TEXT NOT NULL,
    primary_identifier VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_json TEXT NOT NULL,
    package_name VARCHAR(255),
    package_version VARCHAR(255),
    fixed_version VARCHAR(255),
    artifact_name TEXT,
    artifact_type VARCHAR(120),
    artifact_path TEXT,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    present_in_latest_scan BOOLEAN NOT NULL,
    status VARCHAR(50) NOT NULL,
    references_json TEXT NOT NULL,
    source_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_target_id) REFERENCES asset_nodes(id) ON DELETE CASCADE,
    UNIQUE (scan_target_id, dedupe_key)
);

CREATE TABLE finding_comments (
    id VARCHAR PRIMARY KEY NOT NULL,
    finding_id VARCHAR NOT NULL,
    project_id VARCHAR NOT NULL,
    author_principal_type VARCHAR(20) NOT NULL,
    author_principal_id VARCHAR(36) NOT NULL,
    body TEXT NOT NULL,
    is_system BOOLEAN NOT NULL,
    status_from VARCHAR(50),
    status_to VARCHAR(50),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES raw_finding_instances(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE finding_status_change_requests (
    id VARCHAR PRIMARY KEY NOT NULL,
    finding_id VARCHAR NOT NULL,
    project_id VARCHAR NOT NULL,
    requester_principal_type VARCHAR(20) NOT NULL,
    requester_principal_id VARCHAR(36) NOT NULL,
    reviewer_principal_type VARCHAR(20),
    reviewer_principal_id VARCHAR(36),
    from_status VARCHAR(50) NOT NULL,
    to_status VARCHAR(50) NOT NULL,
    state VARCHAR(20) NOT NULL,
    comment TEXT,
    decision_comment TEXT,
    decided_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES raw_finding_instances(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE user_sessions (
    id VARCHAR PRIMARY KEY NOT NULL,
    user_id VARCHAR NOT NULL,
    token_digest VARCHAR(64) NOT NULL,
    user_agent TEXT,
    ip_address VARCHAR(64),
    expires_at DATETIME NOT NULL,
    idle_expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    last_seen_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE users (
    id VARCHAR PRIMARY KEY NOT NULL,
    username VARCHAR(150) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    is_active BOOLEAN NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE user_password_credentials (
    id VARCHAR PRIMARY KEY NOT NULL,
    user_id VARCHAR NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
