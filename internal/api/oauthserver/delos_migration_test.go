package oauthserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (ts *OAuthClientTestSuite) TestDelosMigrationPreservesSourceAndRequiresPolicy() {
	client, _ := ts.createTestOAuthClient()
	ts.Require().NoError(ts.DB.RawQuery("UPDATE auth.oauth_clients SET client_type = 'public', client_secret_hash = '', token_endpoint_auth_method = 'none' WHERE id = ?", client.ID).Exec())
	user := ts.createTestUser("migration@example.test")
	session, err := models.NewSession(user.ID, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.DB.Create(session))
	method := models.PasswordGrant.String()
	at := time.Now().Add(-time.Minute)
	ts.Require().NoError(models.CopyDelosOAuthProof(ts.DB, session.ID, []models.AMRClaim{{AuthenticationMethod: &method, CreatedAt: at, UpdatedAt: at}}, models.AAL1, nil))
	oldFlag := ts.Config.OAuthServer.DelosPolicyEnabled
	ts.Config.OAuthServer.DelosPolicyEnabled = true
	defer func() { ts.Config.OAuthServer.DelosPolicyEnabled = oldFlag }()
	invoke := func(redirect string) (*httptest.ResponseRecorder, error) {
		body, err := json.Marshal(map[string]any{"client_id": client.ID, "redirect_uri": redirect, "state": strings.Repeat("s", 43), "code_challenge": strings.Repeat("c", 43)})
		ts.Require().NoError(err)
		r := httptest.NewRequest(http.MethodPost, "/oauth/migrate-session", strings.NewReader(string(body)))
		ctx := shared.WithUser(r.Context(), user)
		ctx = shared.WithSession(ctx, session)
		w := httptest.NewRecorder()
		return w, ts.Server.DelosMigrateSession(w, r.WithContext(ctx))
	}
	_, err = invoke("https://example.com/callback")
	ts.Require().Error(err)
	ts.Require().NoError(ts.DB.RawQuery("INSERT INTO auth.delos_oauth_client_policies (client_id, client_key, allowed_scopes, access_mode, resource, enabled, allow_session_migration) VALUES (?, 'test-first-party', 'openid offline_access', 'full', '', true, true)", client.ID).Exec())
	_, err = invoke("https://attacker.example/callback")
	ts.Require().Error(err)
	w, err := invoke("https://example.com/callback")
	ts.Require().NoError(err)
	var response struct {
		Code string `json:"code"`
	}
	ts.Require().NoError(json.Unmarshal(w.Body.Bytes(), &response))
	authorization, err := models.FindOAuthServerAuthorizationByCode(ts.DB, response.Code)
	ts.Require().NoError(err)
	ts.Require().Equal(session.ID, *authorization.DelosSourceSessionID)
	ts.Require().Equal("aal1", *authorization.DelosSourceAAL)
	ts.Require().Error(authorization.VerifyPKCE("not-the-verifier"))
	// Creating a replacement code never consumes/revokes the user's old session.
	_, err = models.FindSessionByID(ts.DB, session.ID, false)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.DB.RawQuery("UPDATE auth.delos_oauth_client_policies SET require_aal2 = true WHERE client_id = ?", client.ID).Exec())
	_, err = invoke("https://example.com/callback")
	ts.Require().Error(err)
	// No fake MFA from the old access-token hook can bypass persisted proof.
	ts.Require().NoError(ts.DB.RawQuery("UPDATE auth.sessions SET aal = 'aal2' WHERE id = ?", session.ID).Exec())
	_, err = invoke("https://example.com/callback")
	ts.Require().Error(err)
}
