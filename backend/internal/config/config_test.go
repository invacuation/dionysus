package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if settings.Environment != "local" {
		t.Fatalf("Environment = %q, want local", settings.Environment)
	}
	if settings.DatabaseURL != "sqlite:///../var/dionysus.db" {
		t.Fatalf("DatabaseURL = %q, want sqlite:///../var/dionysus.db", settings.DatabaseURL)
	}
	if settings.HTTPAddr != ":8000" {
		t.Fatalf("HTTPAddr = %q, want :8000", settings.HTTPAddr)
	}
	if settings.SessionIdleTimeoutMinutes != 30 {
		t.Fatalf("SessionIdleTimeoutMinutes = %d, want 30", settings.SessionIdleTimeoutMinutes)
	}
	if settings.SessionAbsoluteTimeoutMinutes != 480 {
		t.Fatalf("SessionAbsoluteTimeoutMinutes = %d, want 480", settings.SessionAbsoluteTimeoutMinutes)
	}
	if settings.MachineAccessTokenExpiresMinutes != 15 {
		t.Fatalf("MachineAccessTokenExpiresMinutes = %d, want 15", settings.MachineAccessTokenExpiresMinutes)
	}
	if settings.MachineRefreshTokenExpiresMinutes != 60 {
		t.Fatalf("MachineRefreshTokenExpiresMinutes = %d, want 60", settings.MachineRefreshTokenExpiresMinutes)
	}
	if !settings.LocalAuthEnabled {
		t.Fatal("LocalAuthEnabled = false, want true")
	}
	if settings.RawReportStorageBackend != "none" {
		t.Fatalf("RawReportStorageBackend = %q, want none", settings.RawReportStorageBackend)
	}
	if settings.RawReportRetentionDays != 0 {
		t.Fatalf("RawReportRetentionDays = %d, want 0", settings.RawReportRetentionDays)
	}
	if settings.MaxReportUploadBytes != 25*1024*1024 {
		t.Fatalf("MaxReportUploadBytes = %d, want 26214400", settings.MaxReportUploadBytes)
	}
	if settings.FrontendDist != "../frontend/dist" {
		t.Fatalf("FrontendDist = %q, want ../frontend/dist", settings.FrontendDist)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("DIONYSUS_ENVIRONMENT", "test")
	t.Setenv("DIONYSUS_DATABASE_URL", "sqlite:///tmp/dionysus.db")
	t.Setenv("DIONYSUS_HTTP_ADDR", "127.0.0.1:18080")
	t.Setenv("DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES", "10")
	t.Setenv("DIONYSUS_SESSION_ABSOLUTE_TIMEOUT_MINUTES", "60")
	t.Setenv("DIONYSUS_MACHINE_ACCESS_TOKEN_EXPIRES_MINUTES", "5")
	t.Setenv("DIONYSUS_MACHINE_REFRESH_TOKEN_EXPIRES_MINUTES", "30")
	t.Setenv("DIONYSUS_LOCAL_AUTH_ENABLED", "false")
	t.Setenv("DIONYSUS_BOOTSTRAP_ADMIN_USERNAME", "admin")
	t.Setenv("DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD", "change-me-now-please")
	t.Setenv("DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME", "Local Admin")
	t.Setenv("DIONYSUS_RAW_REPORT_STORAGE_BACKEND", "local")
	t.Setenv("DIONYSUS_RAW_REPORT_RETENTION_DAYS", "7")
	t.Setenv("DIONYSUS_MAX_REPORT_UPLOAD_BYTES", "10485760")
	t.Setenv("DIONYSUS_FRONTEND_DIST", "/tmp/frontend/dist")

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if settings.Environment != "test" {
		t.Fatalf("Environment = %q, want test", settings.Environment)
	}
	if settings.DatabaseURL != "sqlite:///tmp/dionysus.db" {
		t.Fatalf("DatabaseURL = %q, want sqlite:///tmp/dionysus.db", settings.DatabaseURL)
	}
	if settings.HTTPAddr != "127.0.0.1:18080" {
		t.Fatalf("HTTPAddr = %q, want 127.0.0.1:18080", settings.HTTPAddr)
	}
	if settings.SessionIdleTimeoutMinutes != 10 {
		t.Fatalf("SessionIdleTimeoutMinutes = %d, want 10", settings.SessionIdleTimeoutMinutes)
	}
	if settings.SessionAbsoluteTimeoutMinutes != 60 {
		t.Fatalf("SessionAbsoluteTimeoutMinutes = %d, want 60", settings.SessionAbsoluteTimeoutMinutes)
	}
	if settings.MachineAccessTokenExpiresMinutes != 5 {
		t.Fatalf("MachineAccessTokenExpiresMinutes = %d, want 5", settings.MachineAccessTokenExpiresMinutes)
	}
	if settings.MachineRefreshTokenExpiresMinutes != 30 {
		t.Fatalf("MachineRefreshTokenExpiresMinutes = %d, want 30", settings.MachineRefreshTokenExpiresMinutes)
	}
	if settings.LocalAuthEnabled {
		t.Fatal("LocalAuthEnabled = true, want false")
	}
	if settings.BootstrapAdminUsername != "admin" {
		t.Fatalf("BootstrapAdminUsername = %q, want admin", settings.BootstrapAdminUsername)
	}
	if settings.BootstrapAdminPassword != "change-me-now-please" {
		t.Fatalf("BootstrapAdminPassword = %q, want change-me-now-please", settings.BootstrapAdminPassword)
	}
	if settings.BootstrapAdminDisplayName != "Local Admin" {
		t.Fatalf("BootstrapAdminDisplayName = %q, want Local Admin", settings.BootstrapAdminDisplayName)
	}
	if settings.RawReportStorageBackend != "local" {
		t.Fatalf("RawReportStorageBackend = %q, want local", settings.RawReportStorageBackend)
	}
	if settings.RawReportRetentionDays != 7 {
		t.Fatalf("RawReportRetentionDays = %d, want 7", settings.RawReportRetentionDays)
	}
	if settings.MaxReportUploadBytes != 10*1024*1024 {
		t.Fatalf("MaxReportUploadBytes = %d, want 10485760", settings.MaxReportUploadBytes)
	}
	if settings.FrontendDist != "/tmp/frontend/dist" {
		t.Fatalf("FrontendDist = %q, want /tmp/frontend/dist", settings.FrontendDist)
	}
}

func TestLoadRejectsInvalidInteger(t *testing.T) {
	clearEnv(t)
	t.Setenv("DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES", "not-an-int")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func clearEnv(t *testing.T) {
	t.Helper()
	names := []string{
		"DIONYSUS_ENVIRONMENT",
		"DIONYSUS_DATABASE_URL",
		"DIONYSUS_HTTP_ADDR",
		"DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES",
		"DIONYSUS_SESSION_ABSOLUTE_TIMEOUT_MINUTES",
		"DIONYSUS_MACHINE_ACCESS_TOKEN_EXPIRES_MINUTES",
		"DIONYSUS_MACHINE_REFRESH_TOKEN_EXPIRES_MINUTES",
		"DIONYSUS_LOCAL_AUTH_ENABLED",
		"DIONYSUS_BOOTSTRAP_ADMIN_USERNAME",
		"DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD",
		"DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME",
		"DIONYSUS_RAW_REPORT_STORAGE_BACKEND",
		"DIONYSUS_RAW_REPORT_RETENTION_DAYS",
		"DIONYSUS_MAX_REPORT_UPLOAD_BYTES",
		"DIONYSUS_FRONTEND_DIST",
	}
	for _, name := range names {
		t.Setenv(name, "")
	}
}
