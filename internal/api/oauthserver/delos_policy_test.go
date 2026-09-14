package oauthserver

import (
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"testing"
)

func TestDelosScopeValidationIsOptIn(t *testing.T) {
	cfg := &conf.GlobalConfiguration{}
	s := NewServer(cfg, nil, nil)
	require.NoError(t, s.validateScopes("openid profile offline_access"))
	require.Error(t, s.validateScopes("workers:message"))
	cfg.OAuthServer.DelosPolicyEnabled = true
	// Syntax acceptance only: authorization subsequently requires DB registry
	// and per-client policy. Turning the flag on does not authorize a grant.
	require.NoError(t, s.validateScopes("workers:message"))
	require.Error(t, s.validateScopes("workers:message\nopenid"))
	require.Error(t, s.validateScopes(""))
	require.Error(t, s.validateScopes("*"))
}
