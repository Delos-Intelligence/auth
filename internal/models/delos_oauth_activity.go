package models

import (
	"context"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/storage"
)

type DelosOAuthActivity struct {
	Bucket     time.Time `db:"bucket" json:"bucket"`
	Protocol   string    `db:"protocol" json:"protocol"`
	ClientKey  string    `db:"client_key" json:"client_key"`
	Event      string    `db:"event" json:"event"`
	Outcome    string    `db:"outcome" json:"outcome"`
	Count      int64     `db:"count" json:"count"`
	LastSeenAt time.Time `db:"last_seen_at" json:"last_seen_at"`
}

func (DelosOAuthActivity) TableName() string { return "delos_oauth_activity" }

type DelosOAuthLegacySession struct {
	SessionID uuid.UUID `db:"session_id"`
	ClientKey string    `db:"client_key"`
	LinkedAt  time.Time `db:"linked_at"`
}

func (DelosOAuthLegacySession) TableName() string { return "delos_oauth_legacy_sessions" }

type DelosOAuthObservation struct {
	Singleton bool      `db:"singleton"`
	StartedAt time.Time `db:"started_at" json:"started_at"`
}

func (DelosOAuthObservation) TableName() string { return "delos_oauth_observation" }

func WriteDelosOAuthActivity(db *storage.Connection, protocol, clientKey, event, outcome string) error {
	table := (&pop.Model{Value: DelosOAuthActivity{}}).TableName()
	return db.RawQuery("INSERT INTO "+table+" AS activity (bucket, protocol, client_key, event, outcome) VALUES (date_trunc('hour', now()), ?, ?, ?, ?) ON CONFLICT (bucket, protocol, client_key, event, outcome) DO UPDATE SET count = activity.count + 1, last_seen_at = now()", protocol, clientKey, event, outcome).Exec()
}

// Best effort and bounded: telemetry must never revoke or fail an issued token.
// Failures are observable even when the database cannot persist the measurement.
func ObserveDelosOAuthActivity(ctx context.Context, db *storage.Connection, protocol, clientKey, event string, success bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	outcome := "error"
	if success {
		outcome = "success"
	}
	if err := WriteDelosOAuthActivity(db.WithContext(ctx), protocol, clientKey, event, outcome); err != nil {
		logrus.WithFields(logrus.Fields{"oauth_protocol": protocol, "oauth_event": event}).Warn("oauth_activity_write_failed")
	}
}
