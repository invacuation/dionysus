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
