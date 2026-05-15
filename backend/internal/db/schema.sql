CREATE TABLE app_security_settings (
    id VARCHAR(50) PRIMARY KEY NOT NULL,
    force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
    session_idle_timeout_minutes INTEGER,
    session_absolute_timeout_minutes INTEGER,
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
