package oauthserver

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var delosS256Challenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// DelosMigrateSession creates a PKCE-bound code from an existing full session.
// It is limited to an administrator-approved first-party full client. The same
// persisted source/AMR/MFA checks as interactive consent and code exchange apply.
// No user metadata assertion, MFA upgrade, or legacy refresh-token relabeling.
func (s *Server) DelosMigrateSession(w http.ResponseWriter, r *http.Request) error {
	shared.SetTokenResponseHeaders(w)
	if !s.config.OAuthServer.Enabled || !s.config.OAuthServer.DelosPolicyEnabled {
		return apierrors.NewOAuthError("access_denied", "Session migration is unavailable")
	}
	var input struct {
		ClientID      uuid.UUID `json:"client_id"`
		RedirectURI   string    `json:"redirect_uri"`
		CodeChallenge string    `json:"code_challenge"`
		State         string    `json:"state"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF || !delosS256Challenge.MatchString(input.CodeChallenge) || !delosS256Challenge.MatchString(input.State) {
		return apierrors.NewOAuthError("invalid_request", "Invalid migration request")
	}
	source, user := shared.GetSession(r.Context()), shared.GetUser(r.Context())
	if source == nil || user == nil || source.OAuthClientID != nil || user.IsAnonymous || user.IsBanned() {
		return apierrors.NewOAuthError("access_denied", "An existing direct full session is required")
	}
	db := s.db.WithContext(r.Context())
	client, err := models.FindOAuthServerClientByID(db, input.ClientID)
	if err != nil {
		return apierrors.NewOAuthError("invalid_client", "Client is unavailable")
	}
	if !client.IsPublic() || !s.isValidRedirectURI(client, input.RedirectURI) {
		return apierrors.NewOAuthError("access_denied", "Client or callback is not eligible for migration")
	}
	var authorization *models.OAuthServerAuthorization
	err = db.Transaction(func(tx *storage.Connection) error {
		var policy models.DelosOAuthClientPolicy
		if err := tx.Where("client_id = ?", client.ID).First(&policy); err != nil {
			return apierrors.NewOAuthError("access_denied", "Client policy is unavailable")
		}
		if !policy.AllowSessionMigration || policy.ClientKey == nil || policy.AccessMode != "full" || policy.Resource != "" {
			return apierrors.NewOAuthError("access_denied", "Client is not approved for migration")
		}
		authorization = models.NewOAuthServerAuthorization(models.NewOAuthServerAuthorizationParams{
			ClientID: client.ID, RedirectURI: input.RedirectURI, Scope: policy.AllowedScopes,
			State: input.State, CodeChallenge: input.CodeChallenge, CodeChallengeMethod: "S256", TTL: 2 * time.Minute,
		})
		if err := models.CreateOAuthServerAuthorization(tx, authorization); err != nil {
			return err
		}
		if err := authorization.SetUser(tx, user.ID); err != nil {
			return err
		}
		if err := s.bindDelosSource(tx, r.Context(), authorization, user); err != nil {
			return err
		}
		return authorization.Approve(tx)
	})
	if err != nil {
		return err
	}
	return shared.SendJSON(w, http.StatusOK, map[string]any{"code": authorization.AuthorizationCode, "state": input.State})
}
