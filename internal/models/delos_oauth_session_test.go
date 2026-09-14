package models

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

func TestDelosOAuthSessionProof(t *testing.T) {
	now := time.Now().UTC()
	userID, factorID := uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4())
	password, totp, saml, recovery := PasswordGrant.String(), TOTPSignIn.String(), SSOSAML.String(), Recovery.String()
	claim := func(method *string) AMRClaim {
		return AMRClaim{AuthenticationMethod: method, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute)}
	}
	user := User{ID: userID}
	source := Session{UserID: userID, CreatedAt: now.Add(-time.Hour), AMRClaims: []AMRClaim{claim(&password)}}
	verify := func(s *Session, u *User, expected string, mfa bool) error {
		_, _, err := DelosOAuthProof(s, u, now, expected, mfa, SessionValidityConfig{}, now)
		return err
	}
	t.Run("password session", func(t *testing.T) { require.NoError(t, verify(&source, &user, "aal1", false)) })
	t.Run("SAML identity needs no email lookup", func(t *testing.T) {
		s := source
		s.AMRClaims = []AMRClaim{claim(&saml)}
		require.NoError(t, verify(&s, &user, "aal1", false))
		require.ErrorIs(t, verify(&s, &user, "aal2", true), ErrDelosOAuthPolicy)
	})
	t.Run("user-wide MFA stamp is not evidence", func(t *testing.T) {
		u := user
		u.AppMetaData = map[string]interface{}{"delos_aal": "aal2"}
		require.ErrorIs(t, verify(&source, &u, "aal2", true), ErrDelosOAuthPolicy)
	})
	t.Run("wrong subject", func(t *testing.T) {
		u := user
		u.ID = uuid.Must(uuid.NewV4())
		require.Error(t, verify(&source, &u, "aal1", false))
	})
	t.Run("missing source", func(t *testing.T) { require.Error(t, verify(nil, &user, "aal1", false)) })
	t.Run("expired source", func(t *testing.T) {
		s := source
		deadline := now.Add(-time.Second)
		s.NotAfter = &deadline
		require.Error(t, verify(&s, &user, "aal1", false))
	})
	t.Run("anonymous source", func(t *testing.T) {
		u := user
		u.IsAnonymous = true
		require.Error(t, verify(&source, &u, "aal1", false))
	})
	t.Run("recovery source", func(t *testing.T) {
		s := source
		s.AMRClaims = []AMRClaim{claim(&recovery)}
		require.Error(t, verify(&s, &user, "aal1", false))
	})
	t.Run("delegated source cannot authorize a new session", func(t *testing.T) {
		s := source
		mode := "delegated"
		s.DelosAccessMode = &mode
		require.Error(t, verify(&s, &user, "aal1", false))
		_, _, err := DelosSessionProof(&s, &user, now, "aal1", false, SessionValidityConfig{}, now)
		require.NoError(t, err, "delegated evidence remains valid for its own resource")
	})
	t.Run("verified MFA timestamps survive", func(t *testing.T) {
		s, u := source, user
		s.AMRClaims = []AMRClaim{claim(&password), claim(&totp)}
		s.FactorID = &factorID
		u.Factors = []Factor{{ID: factorID, Status: FactorStateVerified.String()}}
		evidence, aal, err := DelosOAuthProof(&s, &u, now, "aal2", true, SessionValidityConfig{}, now)
		require.NoError(t, err)
		require.Equal(t, AAL2, aal)
		require.Equal(t, s.AMRClaims, evidence)
		u.Factors = nil
		require.Error(t, verify(&s, &u, "aal2", true))
	})
	t.Run("MFA performed after approval cannot upgrade grant", func(t *testing.T) {
		s, u := source, user
		late := claim(&totp)
		late.UpdatedAt = now.Add(time.Second)
		s.AMRClaims = []AMRClaim{claim(&password), late}
		s.FactorID = &factorID
		u.Factors = []Factor{{ID: factorID, Status: FactorStateVerified.String()}}
		require.Error(t, verify(&s, &u, "aal1", false))
	})
}
