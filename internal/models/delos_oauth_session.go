package models

import (
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/storage"
)

// DelosOAuthProof uses persisted authentication evidence, never app_metadata
// or a client-provided AAL. Approval cannot acquire stronger MFA after the fact.
func DelosOAuthProof(source *Session, user *User, approvedAt time.Time, expectedAAL string, requireAAL2 bool, validity SessionValidityConfig, now time.Time) ([]AMRClaim, AuthenticatorAssuranceLevel, error) {
	if source != nil && source.DelosAccessMode != nil && *source.DelosAccessMode != "full" {
		return nil, AAL1, ErrDelosOAuthPolicy
	}
	return DelosSessionProof(source, user, approvedAt, expectedAAL, requireAAL2, validity, now)
}

// DelosSessionProof also validates an already issued delegated session. Such a
// session can access its resource, but DelosOAuthProof refuses it as a source
// for issuing another grant.
func DelosSessionProof(source *Session, user *User, approvedAt time.Time, expectedAAL string, requireAAL2 bool, validity SessionValidityConfig, now time.Time) ([]AMRClaim, AuthenticatorAssuranceLevel, error) {
	if source == nil || source.UserID != user.ID || user.IsAnonymous || user.IsBanned() ||
		source.CheckValidity(validity, now, nil, user.HighestPossibleAAL()) != SessionValid {
		return nil, AAL1, ErrDelosOAuthPolicy
	}
	var evidence []AMRClaim
	for _, claim := range source.AMRClaims {
		method := claim.GetAuthenticationMethod()
		if method == Recovery.String() || method == Anonymous.String() {
			return nil, AAL1, ErrDelosOAuthPolicy
		}
		if method == "" || method == OAuthProviderAuthorizationCode.String() || claim.UpdatedAt.After(approvedAt) {
			continue
		}
		evidence = append(evidence, claim)
	}
	if len(evidence) == 0 {
		return nil, AAL1, ErrDelosOAuthPolicy
	}
	snapshot := *source
	snapshot.AMRClaims = evidence
	aal, _, err := snapshot.CalculateAALAndAMR(user)
	if err != nil {
		return nil, AAL1, err
	}
	if expectedAAL != "" && aal.String() != expectedAAL {
		return nil, AAL1, ErrDelosOAuthPolicy
	}
	if (requireAAL2 || user.HighestPossibleAAL() == AAL2) && aal != AAL2 {
		return nil, AAL1, ErrDelosOAuthPolicy
	}
	if aal == AAL2 && !HasVerifiedDelosFactor(source, user) {
		return nil, AAL1, ErrDelosOAuthPolicy
	}

	return evidence, aal, nil
}

// Copy authentication timestamps verbatim; issuing an OAuth code is not a new MFA challenge.
func CopyDelosOAuthProof(tx *storage.Connection, sessionID uuid.UUID, evidence []AMRClaim, aal AuthenticatorAssuranceLevel, factorID *uuid.UUID) error {
	for _, source := range evidence {
		claim := source
		claim.ID = uuid.Must(uuid.NewV4())
		claim.SessionID = sessionID
		if err := tx.RawQuery("INSERT INTO "+(&pop.Model{Value: AMRClaim{}}).TableName()+" (id, session_id, created_at, updated_at, authentication_method) VALUES (?, ?, ?, ?, ?)", claim.ID, claim.SessionID, claim.CreatedAt, claim.UpdatedAt, claim.AuthenticationMethod).Exec(); err != nil {
			return err
		}
	}
	session := &Session{ID: sessionID}
	return session.UpdateAALAndAssociatedFactor(tx, aal, factorID)
}

func HasVerifiedDelosFactor(session *Session, user *User) bool {
	if session.FactorID == nil {
		return false
	}
	for _, factor := range user.Factors {
		if factor.ID == *session.FactorID && factor.Status == FactorStateVerified.String() {
			return true
		}
	}
	return false
}
