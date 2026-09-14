package api

import (
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/models"
)

// Exercise the actual authentication middleware, including database reloads.
// A resource server must observe revocation before the access JWT expires.
func (ts *AuthTestSuite) TestDelosAccessPolicyChanges() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	client := &models.OAuthServerClient{
		ID: uuid.Must(uuid.NewV4()), ClientType: models.OAuthServerClientTypePublic,
		RegistrationType: "manual", GrantTypes: "authorization_code,refresh_token",
		RedirectURIs: "https://example.com/callback",
	}
	ts.Require().NoError(models.CreateOAuthServerClient(ts.API.db, client))
	mode, scope, resource, aal := "delegated", "openid", "https://example.com/mcp", "aal1"
	session, err := models.NewSession(u.ID, nil)
	ts.Require().NoError(err)
	session.OAuthClientID, session.DelosAccessMode, session.DelosResource, session.Scopes, session.AAL = &client.ID, &mode, &resource, &scope, &aal
	ts.Require().NoError(ts.API.db.Create(session))
	method := models.PasswordGrant.String()
	now := time.Now().Add(-time.Second)
	proof := []models.AMRClaim{{AuthenticationMethod: &method, CreatedAt: now, UpdatedAt: now}}
	ts.Require().NoError(models.CopyDelosOAuthProof(ts.API.db, session.ID, proof, models.AAL1, nil))
	ts.Require().NoError(ts.API.db.RawQuery("INSERT INTO auth.delos_oauth_client_policies (client_id, allowed_scopes, access_mode, resource, enabled) VALUES (?, ?, ?, ?, true)", client.ID, scope, mode, resource).Exec())
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
		SessionId:        session.ID.String(), ClientID: client.ID.String(), Scope: scope,
		DelosAccessMode: mode, DelosResource: resource, Role: models.DelosDelegatedRole, AuthenticatorAssuranceLevel: aal,
	}
	check := func(path string) error {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
		ts.Require().NoError(err)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		_, err = ts.API.requireAuthentication(httptest.NewRecorder(), req)
		return err
	}
	// No dependency on the rollout flag: already issued sessions remain checked.
	ts.Require().NoError(check("/oauth/userinfo"))
	ts.Require().Error(check("/user"))
	claims.DelosResource += "/other"
	ts.Require().Error(check("/oauth/userinfo"))
	claims.DelosResource = resource
	for _, change := range []string{"enabled = false", "allowed_scopes = 'profile'", "access_mode = 'full'", "require_aal2 = true"} {
		ts.Run(change, func() {
			ts.Require().NoError(ts.API.db.RawQuery("UPDATE auth.delos_oauth_client_policies SET "+change+" WHERE client_id = ?", client.ID).Exec())
			ts.Require().Error(check("/oauth/userinfo"))
			ts.Require().NoError(ts.API.db.RawQuery("UPDATE auth.delos_oauth_client_policies SET enabled = true, allowed_scopes = ?, access_mode = ?, require_aal2 = false WHERE client_id = ?", scope, mode, client.ID).Exec())
			ts.Require().NoError(check("/oauth/userinfo"))
		})
	}
	ts.Require().NoError(ts.API.db.RawQuery("UPDATE auth.oauth_clients SET deleted_at = now() WHERE id = ?", client.ID).Exec())
	ts.Require().Error(check("/oauth/userinfo"))
}
