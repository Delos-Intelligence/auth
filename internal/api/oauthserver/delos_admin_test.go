package oauthserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
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

func (ts *OAuthClientTestSuite) TestDelosClientLookupAndActivity() {
	client, _ := ts.createTestOAuthClient()
	ts.Require().NoError(ts.DB.RawQuery("UPDATE auth.oauth_clients SET client_type = 'public', client_secret_hash = '' WHERE id = ?", client.ID).Exec())
	ts.Require().NoError(ts.DB.RawQuery("INSERT INTO auth.delos_oauth_observation (singleton) VALUES (true) ON CONFLICT DO NOTHING").Exec())
	oldFlag := ts.Config.OAuthServer.DelosPolicyEnabled
	ts.Config.OAuthServer.DelosPolicyEnabled = true
	defer func() { ts.Config.OAuthServer.DelosPolicyEnabled = oldFlag }()
	put := func(enabled bool) {
		body, err := json.Marshal(map[string]any{"client_key": "companion-240822.cosmos.app", "allowed_scopes": "openid email offline_access", "access_mode": "full", "resource": "", "enabled": enabled})
		ts.Require().NoError(err)
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
		req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
		ts.Require().NoError(ts.Server.DelosPolicyPut(httptest.NewRecorder(), req))
	}
	lookup := func() error {
		req := httptest.NewRequest(http.MethodGet, "/oauth/clients/by-key/companion-240822.cosmos.app", nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("client_key", "companion-240822.cosmos.app")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		err := ts.Server.DelosClientConfig(w, req)
		if err == nil {
			ts.Require().Contains(w.Body.String(), client.ID.String())
			ts.Require().NotContains(w.Body.String(), "secret")
		}
		return err
	}
	ts.Require().Error(lookup())
	put(true)
	ts.Require().NoError(lookup())
	put(false)
	ts.Require().Error(lookup())
	for i := 0; i < 3; i++ {
		ts.Require().NoError(models.WriteDelosOAuthActivity(ts.DB, "legacy", "companion-240822.cosmos.app", "refresh", "success"))
	}
	ts.Require().NoError(models.WriteDelosOAuthActivity(ts.DB, "native", client.ID.String(), "signin", "success"))
	w := httptest.NewRecorder()
	ts.Require().NoError(ts.Server.DelosActivity(w, httptest.NewRequest(http.MethodGet, "/admin/oauth/activity?days=30", nil)))
	var result struct {
		Activity []models.DelosOAuthActivity `json:"activity"`
		Coverage string                      `json:"legacy_session_coverage"`
	}
	ts.Require().NoError(json.Unmarshal(w.Body.Bytes(), &result))
	ts.Require().Len(result.Activity, 2)
	ts.Require().Equal("sessions_linked_after_instrumentation_only", result.Coverage)
	for _, event := range result.Activity {
		if event.Protocol == "legacy" {
			ts.Require().Equal(int64(3), event.Count)
		}
	}
}
