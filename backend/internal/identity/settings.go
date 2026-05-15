package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

const AppSecuritySettingsID = "default"

func GetOrCreateSecuritySettings(ctx context.Context, conn *sql.DB, now time.Time) (dbgen.AppSecuritySetting, error) {
	queries := dbgen.New(conn)
	settings, err := queries.GetAppSecuritySettings(ctx, AppSecuritySettingsID)
	if errors.Is(err, sql.ErrNoRows) {
		return queries.CreateAppSecuritySettings(ctx, dbgen.CreateAppSecuritySettingsParams{
			ID:                              AppSecuritySettingsID,
			ForcePeerReviewForStatusChanges: false,
			CreatedAt:                       now.UTC(),
			UpdatedAt:                       now.UTC(),
		})
	}
	return settings, err
}

func UpdateSecuritySettings(
	ctx context.Context,
	conn *sql.DB,
	forcePeerReviewForStatusChanges bool,
	sessionIdleTimeoutMinutes int,
	sessionAbsoluteTimeoutMinutes int,
	now time.Time,
) (dbgen.AppSecuritySetting, error) {
	queries := dbgen.New(conn)
	if _, err := GetOrCreateSecuritySettings(ctx, conn, now); err != nil {
		return dbgen.AppSecuritySetting{}, err
	}
	return queries.UpdateAppSecuritySettings(ctx, dbgen.UpdateAppSecuritySettingsParams{
		ForcePeerReviewForStatusChanges: forcePeerReviewForStatusChanges,
		SessionIdleTimeoutMinutes:       sql.NullInt64{Int64: int64(sessionIdleTimeoutMinutes), Valid: true},
		SessionAbsoluteTimeoutMinutes:   sql.NullInt64{Int64: int64(sessionAbsoluteTimeoutMinutes), Valid: true},
		UpdatedAt:                       now.UTC(),
		ID:                              AppSecuritySettingsID,
	})
}
