package models

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestDelosOAuthPolicy(t *testing.T) {
	base := DelosOAuthClientPolicy{Enabled: true, AccessMode: "delegated", AllowedScopes: "openid workers:message offline_access", Resource: "https://api.example.test/mcp-workers/123"}
	tests := []struct {
		name, scope, resource, mode string
		disabled, denied            bool
	}{
		{"scoped grant", "openid workers:message", base.Resource, "delegated", false, false},
		{"unregistered scope", "mail:send", base.Resource, "delegated", false, true},
		{"different worker", "workers:message", "https://api.example.test/mcp-workers/456", "delegated", false, true},
		{"missing resource", "workers:message", "", "delegated", false, true},
		{"resource suffix", "workers:message", base.Resource + "/other", "delegated", false, true},
		{"disabled", "workers:message", base.Resource, "delegated", true, true},
		{"missing scopes", "", base.Resource, "delegated", false, true},
		{"unknown mode", "openid", base.Resource, "unknown", false, true},
		{"full cannot carry custom grant", "workers:message", base.Resource, "full", false, true},
		{"standard scope allowed", "openid", base.Resource, "full", false, false},
		{"no scope injection", "openid\nworkers:message", base.Resource, "delegated", false, true},
		{"too large", strings.Repeat("openid ", 400), base.Resource, "delegated", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			p.AccessMode = tt.mode
			p.Enabled = !tt.disabled
			err := p.ValidateGrant(tt.scope, tt.resource)
			if tt.denied {
				require.ErrorIs(t, err, ErrDelosOAuthPolicy)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
func TestDelosScopeNames(t *testing.T) {
	for _, name := range []string{"workers:message", "drive:read", "openid", "app.scope-v2", strings.Repeat("a", 128)} {
		require.True(t, ValidDelosScopeName(name), name)
	}
	for _, name := range []string{"", "*", "a b", "a\tb", "a\nb", "é", "scope/other", strings.Repeat("a", 129)} {
		require.False(t, ValidDelosScopeName(name), name)
	}
}
func TestDelosSessionPolicyIsCopiedAtIssuance(t *testing.T) {
	mode, resource := "delegated", "https://api.example.test/mcp-workers/123"
	session := Session{}
	session.ApplyGrantParams(&GrantParams{DelosAccessMode: &mode, DelosResource: &resource})
	require.Equal(t, mode, *session.DelosAccessMode)
	require.Equal(t, resource, *session.DelosResource)
	legacy := Session{}
	legacy.ApplyGrantParams(&GrantParams{})
	require.Nil(t, legacy.DelosAccessMode)
	require.Nil(t, legacy.DelosResource)
}
