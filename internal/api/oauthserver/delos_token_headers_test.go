package oauthserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/shared"
)

func (ts *OAuthClientTestSuite) TestDelosTokenExchangeAndRefreshHeaders() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("token-headers@example.com")
	code := ts.mintApprovedCode(client.ID, user.ID)
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	ctx := shared.WithOAuthServerClient(request.Context(), client)
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	require.NoError(ts.T(), ts.Server.handleAuthorizationCodeGrant(ctx, response, request, &OAuthTokenParams{GrantType: GrantTypeAuthorizationCode, Code: code}))
	require.Equal(ts.T(), http.StatusOK, response.Code)
	require.Contains(ts.T(), response.Header().Get("Cache-Control"), "no-store")
	require.Equal(ts.T(), "no-cache", response.Header().Get("Pragma"))
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(ts.T(), json.Unmarshal(response.Body.Bytes(), &tokens))
	require.NotEmpty(ts.T(), tokens.RefreshToken)
	response = httptest.NewRecorder()
	require.NoError(ts.T(), ts.Server.handleRefreshTokenGrant(ctx, response, request, &OAuthTokenParams{GrantType: GrantTypeRefreshToken, RefreshToken: tokens.RefreshToken}))
	require.Equal(ts.T(), http.StatusOK, response.Code)
	require.Contains(ts.T(), response.Header().Get("Cache-Control"), "no-store")
	require.Equal(ts.T(), "no-cache", response.Header().Get("Pragma"))
}
