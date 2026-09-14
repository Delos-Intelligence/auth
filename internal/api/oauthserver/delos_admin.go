package oauthserver

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gobuffalo/pop/v6"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// These handlers are mounted only behind the existing /admin authentication.
// Public DCR creates a client, never its Delos access policy.
func (s *Server) DelosPolicyGet(w http.ResponseWriter, r *http.Request) error {
	client := shared.GetOAuthServerClient(r.Context())
	var policy models.DelosOAuthClientPolicy
	if err := s.db.WithContext(r.Context()).Where("client_id = ?", client.ID).First(&policy); err != nil {
		if errors.Is(err, sql.ErrNoRows) || models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeOAuthClientNotFound, "Client has no Delos policy")
		}
		return apierrors.NewInternalServerError("Unable to read OAuth policy").WithInternalError(err)
	}
	return shared.SendJSON(w, http.StatusOK, policy)
}

func (s *Server) DelosPolicyPut(w http.ResponseWriter, r *http.Request) error {
	client := shared.GetOAuthServerClient(r.Context())
	var policy *models.DelosOAuthClientPolicy
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil || policy == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Invalid OAuth policy")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Expected a single OAuth policy")
	}
	policy.ClientID = client.ID
	validation := *policy
	validation.Enabled = true // Disabling a valid policy is allowed.
	if policy.AllowSessionMigration && (policy.AccessMode != "full" || policy.ClientKey == nil || !client.IsPublic()) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Session migration requires a named, public first-party full client")
	}
	if policy.ClientKey != nil && !models.ValidDelosScopeName(*policy.ClientKey) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid client lookup key")
	}
	if err := validation.ValidateGrant(policy.AllowedScopes, policy.Resource); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid scopes, mode or resource")
	}
	table := (&pop.Model{Value: models.DelosOAuthClientPolicy{}}).TableName()
	err := s.db.WithContext(r.Context()).Transaction(func(tx *storage.Connection) error {
		if err := tx.RawQuery("INSERT INTO "+table+" (client_id, allowed_scopes, access_mode, resource, enabled, require_aal2, client_key, allow_session_migration) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (client_id) DO UPDATE SET allowed_scopes = EXCLUDED.allowed_scopes, access_mode = EXCLUDED.access_mode, resource = EXCLUDED.resource, enabled = EXCLUDED.enabled, require_aal2 = EXCLUDED.require_aal2, client_key = EXCLUDED.client_key, allow_session_migration = EXCLUDED.allow_session_migration", policy.ClientID, policy.AllowedScopes, policy.AccessMode, policy.Resource, policy.Enabled, policy.RequireAAL2, policy.ClientKey, policy.AllowSessionMigration).Exec(); err != nil {
			return err
		}
		if policy.Enabled {
			_, err := models.FindDelosOAuthPolicy(tx, client.ID, policy.AllowedScopes, policy.Resource)
			return err
		}
		return nil
	})
	if errors.Is(err, models.ErrDelosOAuthPolicy) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Scope is not enabled in the registry")
	}
	if err != nil {
		return apierrors.NewInternalServerError("Unable to save OAuth policy").WithInternalError(err)
	}
	observability.LogEntrySetField(r, "delos_policy_updated", true)
	observability.LogEntrySetField(r, "delos_policy_enabled", policy.Enabled)
	return shared.SendJSON(w, http.StatusOK, policy)
}

func (s *Server) DelosScopesList(w http.ResponseWriter, r *http.Request) error {
	scopes := []models.DelosOAuthScope{}
	if err := s.db.WithContext(r.Context()).Order("name").All(&scopes); err != nil {
		return apierrors.NewInternalServerError("Unable to read OAuth scopes").WithInternalError(err)
	}
	return shared.SendJSON(w, http.StatusOK, map[string]any{"scopes": scopes})
}

func (s *Server) DelosScopePut(w http.ResponseWriter, r *http.Request) error {
	var scope *models.DelosOAuthScope
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scope); err != nil || scope == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Invalid scope definition")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Expected a single scope definition")
	}
	scope.Name = chi.URLParam(r, "scope")
	if !models.ValidDelosScopeName(scope.Name) || models.IsSupportedScope(scope.Name) || len(scope.Description) > 1024 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid custom scope name or description")
	}
	table := (&pop.Model{Value: models.DelosOAuthScope{}}).TableName()
	if err := s.db.WithContext(r.Context()).RawQuery("INSERT INTO "+table+" (name, description, enabled) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, enabled = EXCLUDED.enabled", scope.Name, scope.Description, scope.Enabled).Exec(); err != nil {
		return apierrors.NewInternalServerError("Unable to save OAuth scope").WithInternalError(err)
	}
	observability.LogEntrySetField(r, "delos_scope_updated", scope.Name)
	observability.LogEntrySetField(r, "delos_scope_enabled", scope.Enabled)
	return shared.SendJSON(w, http.StatusOK, scope)
}
