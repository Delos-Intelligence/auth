package oauthserver

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (s *Server) delosPolicy(tx *storage.Connection, clientID uuid.UUID, scope, resource string) (*models.DelosOAuthClientPolicy, error) {
	policy, err := models.FindDelosOAuthPolicy(tx, clientID, scope, resource)
	if errors.Is(err, models.ErrDelosOAuthPolicy) {
		return nil, apierrors.NewOAuthError("access_denied", err.Error())
	}
	if err != nil {
		return nil, apierrors.NewInternalServerError("Unable to validate OAuth policy").WithInternalError(err)
	}
	return policy, nil
}

func (s *Server) validateDelosPolicy(tx *storage.Connection, clientID uuid.UUID, scope, resource string) error {
	if !s.config.OAuthServer.DelosPolicyEnabled {
		return nil
	}
	_, err := s.delosPolicy(tx, clientID, scope, resource)
	return err
}

func (s *Server) bindDelosSource(tx *storage.Connection, ctx context.Context, authorization *models.OAuthServerAuthorization, user *models.User) error {
	if !s.config.OAuthServer.DelosPolicyEnabled {
		return nil
	}
	policy, err := s.delosPolicy(tx, authorization.ClientID, authorization.Scope, stringValue(authorization.Resource))
	if err != nil {
		return err
	}
	source := shared.GetSession(ctx)
	if source == nil {
		return apierrors.NewOAuthError("login_required", "A current session is required")
	}
	// Reload the source inside the consent transaction; context can be stale.
	source, err = models.FindSessionByID(tx, source.ID, false)
	if err != nil {
		return apierrors.NewOAuthError("login_required", "Source session is unavailable")
	}
	_, aal, err := models.DelosOAuthProof(source, user, time.Now(), "", policy.RequireAAL2, s.delosSessionValidity(), time.Now())
	if err != nil {
		return apierrors.NewOAuthError("interaction_required", "Sign in and complete the required MFA")
	}
	authorization.DelosSourceSessionID = &source.ID
	authorization.DelosSourceAAL = aal.PointerString()
	return tx.UpdateOnly(authorization, "delos_source_session_id", "delos_source_aal")
}
func (s *Server) delosSessionValidity() models.SessionValidityConfig {
	return models.SessionValidityConfig{Timebox: s.config.Sessions.Timebox, InactivityTimeout: s.config.Sessions.InactivityTimeout, AllowLowAAL: s.config.Sessions.AllowLowAAL}
}
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
