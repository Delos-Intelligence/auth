package models

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/storage"
)

const DelosDelegatedRole = "oauth_delegated"

var ErrDelosOAuthPolicy = errors.New("OAuth grant is not permitted by the client policy")

// Policies are administrator-owned. Dynamic registration cannot grant access.
// The resource is an exact binding, not an origin/prefix allowlist.
type DelosOAuthClientPolicy struct {
	ClientID      uuid.UUID `db:"client_id" json:"client_id"`
	AllowedScopes string    `db:"allowed_scopes" json:"allowed_scopes"`
	AccessMode    string    `db:"access_mode" json:"access_mode"`
	Resource      string    `db:"resource" json:"resource"`
	Enabled       bool      `db:"enabled" json:"enabled"`
	RequireAAL2   bool      `db:"require_aal2" json:"require_aal2"`
}

func (DelosOAuthClientPolicy) TableName() string { return "delos_oauth_client_policies" }

type DelosOAuthScope struct {
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
	Enabled     bool   `db:"enabled" json:"enabled"`
}

func (DelosOAuthScope) TableName() string { return "delos_oauth_scopes" }

func (p *DelosOAuthClientPolicy) ValidateGrant(scope, resource string) error {
	if !p.Enabled || (p.AccessMode != "full" && p.AccessMode != "delegated") || p.Resource != resource {
		return ErrDelosOAuthPolicy
	}
	if p.AccessMode == "delegated" && resource == "" {
		return ErrDelosOAuthPolicy
	}
	scopes := ParseScopeString(scope)
	if len(scopes) == 0 || len(scope) > 2048 || !HasAllScopes(ParseScopeString(p.AllowedScopes), scopes) {
		return ErrDelosOAuthPolicy
	}
	for _, scope := range scopes {
		if !ValidDelosScopeName(scope) || (p.AccessMode == "full" && !IsSupportedScope(scope)) {
			return ErrDelosOAuthPolicy
		}
	}
	return nil
}

func ValidDelosScopeName(scope string) bool {
	if len(scope) == 0 || len(scope) > 128 {
		return false
	}
	return strings.IndexFunc(scope, func(c rune) bool {
		return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("_:.-", c))
	}) == -1
}

func FindDelosOAuthPolicy(tx *storage.Connection, clientID uuid.UUID, scope, resource string) (*DelosOAuthClientPolicy, error) {
	var policy DelosOAuthClientPolicy
	if err := tx.Where("client_id = ?", clientID).First(&policy); err != nil {
		if errors.Is(err, sql.ErrNoRows) || IsNotFoundError(err) {
			return nil, ErrDelosOAuthPolicy
		}
		return nil, err
	}
	if err := policy.ValidateGrant(scope, resource); err != nil {
		return nil, err
	}
	for _, name := range ParseScopeString(scope) {
		if IsSupportedScope(name) {
			continue
		}
		var definition DelosOAuthScope
		if err := tx.Where("name = ? AND enabled = true", name).First(&definition); err != nil {
			if errors.Is(err, sql.ErrNoRows) || IsNotFoundError(err) {
				return nil, ErrDelosOAuthPolicy
			}
			return nil, err
		}
	}
	return &policy, nil
}
