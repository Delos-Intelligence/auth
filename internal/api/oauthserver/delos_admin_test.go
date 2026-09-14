package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func TestDelosAdminRejectsMalformedBodies(t *testing.T) {
	s := &Server{}
	for _, body := range []string{"null", "[]", "{} {}", `{"unknown":true}`, strings.Repeat("x", 9000)} {
		t.Run(body[:min(len(body), 25)], func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/admin/oauth/clients/test/delos-policy", strings.NewReader(body))
			req = req.WithContext(shared.WithOAuthServerClient(req.Context(), &models.OAuthServerClient{}))
			require.Error(t, s.DelosPolicyPut(httptest.NewRecorder(), req))
			req = httptest.NewRequest(http.MethodPut, "/admin/oauth/scopes/test", strings.NewReader(body))
			require.Error(t, s.DelosScopePut(httptest.NewRecorder(), req))
		})
	}
}

func (ts *OAuthClientTestSuite) TestDelosPolicyAdminRoundtrip() {
	client, _ := ts.createTestOAuthClient()
	put := func(body string) error {
		req := httptest.NewRequest(http.MethodPut, "/admin/oauth/clients/test/delos-policy", strings.NewReader(body))
		req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
		return ts.Server.DelosPolicyPut(httptest.NewRecorder(), req)
	}
	ts.Require().NoError(put(`{"allowed_scopes":"openid email","access_mode":"full","resource":"","enabled":true,"require_aal2":false}`))
	_, err := models.FindDelosOAuthPolicy(ts.DB, client.ID, "openid", "")
	ts.Require().NoError(err)
	// Unknown custom scopes must roll back the policy update atomically.
	ts.Require().Error(put(`{"allowed_scopes":"unknown:scope","access_mode":"delegated","resource":"https://example.com/mcp","enabled":true}`))
	_, err = models.FindDelosOAuthPolicy(ts.DB, client.ID, "openid", "")
	ts.Require().NoError(err)
	// Disabling needs no valid grant or refresh token and takes effect immediately.
	ts.Require().NoError(put(`{"allowed_scopes":"openid email","access_mode":"full","resource":"","enabled":false}`))
	_, err = models.FindDelosOAuthPolicy(ts.DB, client.ID, "openid", "")
	ts.Require().ErrorIs(err, models.ErrDelosOAuthPolicy)
}
