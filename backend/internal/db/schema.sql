CREATE TABLE app_security_settings (
    id VARCHAR(50) PRIMARY KEY NOT NULL,
    force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
    session_idle_timeout_minutes INTEGER,
    session_absolute_timeout_minutes INTEGER,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
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
