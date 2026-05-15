package config

import (
	"fmt"
	"os"
	"strconv"
)

const DefaultMaxReportUploadBytes = 25 * 1024 * 1024

type Settings struct {
	Environment                       string
	DatabaseURL                       string
	SessionIdleTimeoutMinutes         int
	SessionAbsoluteTimeoutMinutes     int
	MachineAccessTokenExpiresMinutes  int
	MachineRefreshTokenExpiresMinutes int
	LocalAuthEnabled                  bool
	BootstrapAdminUsername            string
	BootstrapAdminPassword            string
	BootstrapAdminDisplayName         string
	RawReportStorageBackend           string
	RawReportRetentionDays            int
	MaxReportUploadBytes              int
	FrontendDist                      string
}

func Load() (Settings, error) {
	settings := Settings{
		Environment:                       getenv("DIONYSUS_ENVIRONMENT", "local"),
		DatabaseURL:                       getenv("DIONYSUS_DATABASE_URL", "sqlite:///../var/dionysus.db"),
		SessionIdleTimeoutMinutes:         30,
		SessionAbsoluteTimeoutMinutes:     480,
		MachineAccessTokenExpiresMinutes:  15,
		MachineRefreshTokenExpiresMinutes: 60,
		LocalAuthEnabled:                  true,
		BootstrapAdminUsername:            os.Getenv("DIONYSUS_BOOTSTRAP_ADMIN_USERNAME"),
		BootstrapAdminPassword:            os.Getenv("DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD"),
		BootstrapAdminDisplayName:         os.Getenv("DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME"),
		RawReportStorageBackend:           getenv("DIONYSUS_RAW_REPORT_STORAGE_BACKEND", "none"),
		RawReportRetentionDays:            0,
		MaxReportUploadBytes:              DefaultMaxReportUploadBytes,
		FrontendDist:                      getenv("DIONYSUS_FRONTEND_DIST", "../frontend/dist"),
	}

	var err error
	if settings.SessionIdleTimeoutMinutes, err = intEnv("DIONYSUS_SESSION_IDLE_TIMEOUT_MINUTES", settings.SessionIdleTimeoutMinutes); err != nil {
		return Settings{}, err
	}
	if settings.SessionAbsoluteTimeoutMinutes, err = intEnv("DIONYSUS_SESSION_ABSOLUTE_TIMEOUT_MINUTES", settings.SessionAbsoluteTimeoutMinutes); err != nil {
		return Settings{}, err
	}
	if settings.MachineAccessTokenExpiresMinutes, err = intEnv("DIONYSUS_MACHINE_ACCESS_TOKEN_EXPIRES_MINUTES", settings.MachineAccessTokenExpiresMinutes); err != nil {
		return Settings{}, err
	}
	if settings.MachineRefreshTokenExpiresMinutes, err = intEnv("DIONYSUS_MACHINE_REFRESH_TOKEN_EXPIRES_MINUTES", settings.MachineRefreshTokenExpiresMinutes); err != nil {
		return Settings{}, err
	}
	if settings.RawReportRetentionDays, err = intEnv("DIONYSUS_RAW_REPORT_RETENTION_DAYS", settings.RawReportRetentionDays); err != nil {
		return Settings{}, err
	}
	if settings.MaxReportUploadBytes, err = intEnv("DIONYSUS_MAX_REPORT_UPLOAD_BYTES", settings.MaxReportUploadBytes); err != nil {
		return Settings{}, err
	}
	if settings.LocalAuthEnabled, err = boolEnv("DIONYSUS_LOCAL_AUTH_ENABLED", settings.LocalAuthEnabled); err != nil {
		return Settings{}, err
	}

	return settings, nil
}

func getenv(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func intEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return parsed, nil
}

func boolEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	return parsed, nil
}
