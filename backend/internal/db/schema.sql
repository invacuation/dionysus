CREATE TABLE app_security_settings (
    id VARCHAR(50) PRIMARY KEY NOT NULL,
    force_peer_review_for_status_changes BOOLEAN NOT NULL DEFAULT false,
    session_idle_timeout_minutes INTEGER,
    session_absolute_timeout_minutes INTEGER,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
