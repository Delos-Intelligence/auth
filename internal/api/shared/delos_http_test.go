package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenJSONOverridesCachePolicy(t *testing.T) {
	response := httptest.NewRecorder()
	response.Header().Set("Cache-Control", "public, max-age=600")
	require.NoError(t, SendTokenJSON(response, http.StatusOK, map[string]string{"access_token": "test-token"}))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "no-store, no-cache, must-revalidate", response.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", response.Header().Get("Pragma"))
	require.JSONEq(t, `{"access_token":"test-token"}`, response.Body.String())
}

func TestOrdinaryJSONPreservesCachePolicy(t *testing.T) {
	response := httptest.NewRecorder()
	response.Header().Set("Cache-Control", "public, max-age=600")
	require.NoError(t, SendJSON(response, http.StatusOK, map[string]any{"keys": []any{}}))
	require.Equal(t, "public, max-age=600", response.Header().Get("Cache-Control"))
	require.Empty(t, response.Header().Get("Pragma"))
}
