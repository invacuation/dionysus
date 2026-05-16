package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/invacuation/dionysus/backend/internal/db/dbgen"
)

const redacted = "[REDACTED]"

var sensitiveKeys = map[string]bool{
	"authorization": true,
	"client_secret": true,
	"password":      true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
}

var largeSensitiveKeys = map[string]bool{
	"raw_report":     true,
	"report":         true,
	"report_payload": true,
	"stack":          true,
	"stack_trace":    true,
	"stacktrace":     true,
	"traceback":      true,
}

type Event struct {
	Type               string
	ActorPrincipalType *string
	ActorPrincipalID   *string
	ActorDisplay       *string
	TargetType         *string
	TargetID           *string
	ProjectID          *string
	IPAddress          *string
	UserAgent          *string
	Metadata           map[string]any
	Now                time.Time
}

func RecordEvent(ctx context.Context, conn *sql.DB, event Event) (dbgen.AuditLogEvent, error) {
	eventType := strings.TrimSpace(event.Type)
	if eventType == "" {
		return dbgen.AuditLogEvent{}, errors.New("event_type is required")
	}
	now := event.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	metadataJSON, err := json.Marshal(sanitizeMetadata(event.Metadata))
	if err != nil {
		return dbgen.AuditLogEvent{}, err
	}
	return dbgen.New(conn).CreateAuditLogEvent(ctx, dbgen.CreateAuditLogEventParams{
		ID:                 uuid.NewString(),
		EventType:          eventType,
		ActorPrincipalType: nullString(event.ActorPrincipalType),
		ActorPrincipalID:   nullString(event.ActorPrincipalID),
		ActorDisplay:       nullString(event.ActorDisplay),
		TargetType:         nullString(event.TargetType),
		TargetID:           nullString(event.TargetID),
		ProjectID:          nullString(event.ProjectID),
		IpAddress:          nullString(event.IPAddress),
		UserAgent:          nullString(event.UserAgent),
		MetadataJson:       string(metadataJSON),
		CreatedAt:          now.UTC(),
	})
}

func sanitizeMetadata(metadata map[string]any) map[string]any {
	sanitized := map[string]any{}
	for key, value := range metadata {
		keyText := key
		if isSensitiveKey(keyText) {
			sanitized[keyText] = redacted
			continue
		}
		sanitized[keyText] = sanitizeValue(value)
	}
	return sanitized
}

func sanitizeValue(value any) any {
	if value != nil {
		reflectedValue := reflect.ValueOf(value)
		if (reflectedValue.Kind() == reflect.Pointer || reflectedValue.Kind() == reflect.Interface) && reflectedValue.IsNil() {
			return nil
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeMetadata(typed)
	case []any:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, sanitizeValue(item))
		}
		return items
	case string, int, int64, float64, bool, nil:
		return typed
	default:
		if reflected := sanitizeReflectedValue(reflect.ValueOf(value)); reflected != nil {
			return reflected
		}
		return fmt.Sprint(typed)
	}
}

func sanitizeReflectedValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil
		}
		sanitized := map[string]any{}
		for _, key := range value.MapKeys() {
			keyText := key.String()
			if isSensitiveKey(keyText) {
				sanitized[keyText] = redacted
				continue
			}
			sanitized[keyText] = sanitizeValue(value.MapIndex(key).Interface())
		}
		return sanitized
	case reflect.Slice, reflect.Array:
		items := make([]any, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			items = append(items, sanitizeValue(value.Index(i).Interface()))
		}
		return items
	default:
		return nil
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(key))
	if largeSensitiveKeys[normalized] {
		return true
	}
	for _, part := range strings.Split(normalized, "_") {
		if sensitiveKeys[part] {
			return true
		}
	}
	return false
}

func nullString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
