package oauthserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// Service-role only. The web token endpoint reports its actual validated client
// and issued session. Never expose this ingestion endpoint to public clients.
func (s *Server) DelosLegacyActivity(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		ClientKey string     `json:"client_key"`
		Event     string     `json:"event"`
		Outcome   string     `json:"outcome"`
		SessionID *uuid.UUID `json:"session_id"`
		UserID    *uuid.UUID `json:"user_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF || !models.ValidDelosScopeName(input.ClientKey) || (input.Event != "signin" && input.Event != "refresh") || (input.Outcome != "success" && input.Outcome != "error") {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid activity event")
	}
	db := s.db.WithContext(r.Context())
	err := db.Transaction(func(tx *storage.Connection) error {
		if input.SessionID != nil {
			session, err := models.FindSessionByID(tx, *input.SessionID, false)
			if err != nil {
				return err
			}
			if input.Outcome != "success" || input.UserID == nil || session.UserID != *input.UserID || session.OAuthClientID != nil {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid legacy session association")
			}
			table := (&pop.Model{Value: models.DelosOAuthLegacySession{}}).TableName()
			if err := tx.RawQuery("INSERT INTO "+table+" (session_id, client_key) VALUES (?, ?) ON CONFLICT (session_id) DO NOTHING", session.ID, input.ClientKey).Exec(); err != nil {
				return err
			}
		}
		return models.WriteDelosOAuthActivity(tx, "legacy", input.ClientKey, input.Event, input.Outcome)
	})
	if err != nil {
		return apierrors.NewInternalServerError("Unable to record OAuth activity").WithInternalError(err)
	}
	return shared.SendJSON(w, http.StatusOK, map[string]bool{"recorded": true})
}

// Counts describe observed activity and retained sessions, never installed apps.
// In particular, direct sessions created before instrumentation are unattributed.
func (s *Server) DelosActivity(w http.ResponseWriter, r *http.Request) error {
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || (days != 7 && days != 30 && days != 90) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Choose 7, 30 or 90 days")
	}
	db := s.db.WithContext(r.Context())
	var observation models.DelosOAuthObservation
	if err := db.First(&observation); err != nil {
		return apierrors.NewInternalServerError("Unable to read observation coverage").WithInternalError(err)
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	// Include the first hour in full and return the exact boundary to the UI.
	since = since.Truncate(time.Hour)
	rows := []struct {
		Protocol   string    `db:"protocol" json:"protocol"`
		ClientKey  string    `db:"client_key" json:"client_key"`
		Event      string    `db:"event" json:"event"`
		Outcome    string    `db:"outcome" json:"outcome"`
		Count      int64     `db:"count" json:"count"`
		LastSeenAt time.Time `db:"last_seen_at" json:"last_seen_at"`
	}{}
	table := (&pop.Model{Value: models.DelosOAuthActivity{}}).TableName()
	if err := db.RawQuery("SELECT protocol, client_key, event, outcome, sum(count)::bigint AS count, max(last_seen_at) AS last_seen_at FROM "+table+" WHERE bucket >= ? GROUP BY protocol, client_key, event, outcome ORDER BY client_key, protocol, event, outcome", since).All(&rows); err != nil {
		return apierrors.NewInternalServerError("Unable to read OAuth activity").WithInternalError(err)
	}
	sessionRows := []struct {
		Protocol  string `db:"protocol" json:"protocol"`
		ClientKey string `db:"client_key" json:"client_key"`
		Retained  int64  `db:"retained" json:"retained"`
		Observed  int64  `db:"observed" json:"observed"`
	}{}
	sessions := (&pop.Model{Value: models.Session{}}).TableName()
	legacy := (&pop.Model{Value: models.DelosOAuthLegacySession{}}).TableName()
	if err := db.RawQuery("SELECT 'native' AS protocol, oauth_client_id::text AS client_key, count(*) AS retained, count(*) FILTER (WHERE greatest(created_at, refreshed_at) >= ?) AS observed FROM "+sessions+" WHERE oauth_client_id IS NOT NULL GROUP BY oauth_client_id UNION ALL SELECT 'legacy', l.client_key, count(*), count(*) FILTER (WHERE greatest(s.created_at, s.refreshed_at) >= ?) FROM "+legacy+" l JOIN "+sessions+" s ON s.id = l.session_id GROUP BY l.client_key", since, since).All(&sessionRows); err != nil {
		return apierrors.NewInternalServerError("Unable to read OAuth sessions").WithInternalError(err)
	}

	clients := []struct {
		ClientID  uuid.UUID `db:"client_id" json:"client_id"`
		ClientKey *string   `db:"client_key" json:"client_key"`
		Name      string    `db:"name" json:"name"`
	}{}
	policies := (&pop.Model{Value: models.DelosOAuthClientPolicy{}}).TableName()
	clientTable := (&pop.Model{Value: models.OAuthServerClient{}}).TableName()
	if err := db.RawQuery("SELECT c.id AS client_id, p.client_key, coalesce(c.client_name, c.id::text) AS name FROM " + clientTable + " c LEFT JOIN " + policies + " p ON p.client_id = c.id").All(&clients); err != nil {
		return apierrors.NewInternalServerError("Unable to read client identities").WithInternalError(err)
	}
	lastLegacy := []struct {
		ClientKey  string    `db:"client_key" json:"client_key"`
		LastSeenAt time.Time `db:"last_seen_at" json:"last_seen_at"`
	}{}
	if err := db.RawQuery("SELECT client_key, max(last_seen_at) AS last_seen_at FROM " + table + " WHERE protocol = 'legacy' GROUP BY client_key").All(&lastLegacy); err != nil {
		return apierrors.NewInternalServerError("Unable to read legacy activity").WithInternalError(err)
	}
	return shared.SendJSON(w, http.StatusOK, map[string]any{
		"clients": clients, "last_legacy_activity": lastLegacy, "since": since, "tracking_started_at": observation.StartedAt, "activity": rows, "sessions": sessionRows,
		"legacy_session_coverage": "sessions_linked_after_instrumentation_only",
		"client_version_coverage": "unknown",
	})
}
