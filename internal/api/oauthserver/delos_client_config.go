package oauthserver

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

// DelosClientConfig exposes only public first-party client metadata. An absent
// key fails configuration lookup. Updated clients never fall back to legacy
// login; old installed releases continue to use the separate legacy endpoints.
func (s *Server) DelosClientConfig(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	key := chi.URLParam(r, "client_key")
	if !s.config.OAuthServer.DelosPolicyEnabled || !models.ValidDelosScopeName(key) {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeOAuthClientNotFound, "Client lookup is unavailable")
	}
	db := s.db.WithContext(r.Context())
	var policy models.DelosOAuthClientPolicy
	if err := db.Where("client_key = ?", key).First(&policy); err != nil {
		if errors.Is(err, sql.ErrNoRows) || models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeOAuthClientNotFound, "Client has no native rollout")
		}
		return apierrors.NewInternalServerError("Unable to read client rollout").WithInternalError(err)
	}
	if !policy.Enabled || policy.AccessMode != "full" || policy.Resource != "" || policy.ValidateGrant(policy.AllowedScopes, "") != nil {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNoAuthorization, "Client rollout is not enabled for full account access")
	}
	client, err := models.FindOAuthServerClientByID(db, policy.ClientID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewForbiddenError(apierrors.ErrorCodeNoAuthorization, "Client is no longer available")
		}
		return apierrors.NewInternalServerError("Unable to read OAuth client").WithInternalError(err)
	}
	if !client.IsPublic() {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeNoAuthorization, "Client requires server credentials")
	}
	return shared.SendJSON(w, http.StatusOK, map[string]any{
		"migration_allowed": policy.AllowSessionMigration, "client_id": client.ID.String(), "scope": policy.AllowedScopes, "redirect_uris": client.GetRedirectURIs(),
	})
}
