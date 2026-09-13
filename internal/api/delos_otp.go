package api

import (
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const maxOTPVerificationAttempts = 3

func otpRejected() error {
	return apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid")
}

// Lock the user before inspecting counters. Issuance updates users before replacing
// one_time_tokens, so verification uses the same lock order. A request which read
// an older generation while waiting must not charge a replacement token.
func lockOTPUser(tx *storage.Connection, user *models.User) error {
	previous := *user
	var locked struct {
		ID string `db:"id"`
	}
	if err := tx.RawQuery("SELECT id FROM users WHERE id = ? FOR UPDATE", user.ID).First(&locked); err != nil {
		return apierrors.NewInternalServerError("Error locking verification user").WithInternalError(err)
	}
	if err := tx.Reload(user); err != nil {
		return apierrors.NewInternalServerError("Error reloading verification user").WithInternalError(err)
	}
	if !sameOTPTime(previous.ConfirmationSentAt, user.ConfirmationSentAt) ||
		!sameOTPTime(previous.RecoverySentAt, user.RecoverySentAt) ||
		!sameOTPTime(previous.EmailChangeSentAt, user.EmailChangeSentAt) ||
		!sameOTPTime(previous.PhoneChangeSentAt, user.PhoneChangeSentAt) ||
		previous.ConfirmationToken != user.ConfirmationToken || previous.RecoveryToken != user.RecoveryToken ||
		previous.EmailChangeTokenCurrent != user.EmailChangeTokenCurrent || previous.EmailChangeTokenNew != user.EmailChangeTokenNew ||
		previous.PhoneChangeToken != user.PhoneChangeToken || previous.GetEmail() != user.GetEmail() ||
		previous.EmailChange != user.EmailChange || previous.GetPhone() != user.GetPhone() || previous.PhoneChange != user.PhoneChange {
		return otpRejected()
	}
	return nil
}

// Wrong email-change codes cannot be resolved by token hash. Only charge a counter
// when the destination identifies a single pending user; ambiguous destinations
// retain the generic rejection and endpoint rate limiting.
func findEmailChangeAttemptUser(tx *storage.Connection, email, aud string, secure bool) (*models.User, error) {
	var users []struct {
		ID uuid.UUID `db:"id"`
	}
	err := tx.RawQuery(`SELECT id FROM users WHERE aud = ? AND is_sso_user = false AND
  ((email_change = ? AND email_change_token_new <> '') OR
   (? AND email = ? AND email_change_token_current <> '')) LIMIT 2`, aud, email, secure, email).All(&users)
	if err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, models.UserNotFoundError{}
	}
	return models.FindUserByID(tx, users[0].ID)
}

type otpCandidate struct {
	kind   models.OneTimeTokenType
	hash   string
	sentAt *time.Time
	expiry uint
}

// Called inside the verification transaction, before account/session mutations.
// Only an invalid-code result commits the counter via CommitWithError. Database
// failures fail closed and roll back; successful verification consumes the token
// in this same transaction, without an independent pool or counter reset race.
func (a *API) checkOTPAttempts(tx *storage.Connection, user *models.User, params *VerifyParams, valid bool) error {
	var candidates []otpCandidate
	emailExpiry, phoneExpiry := a.config.Mailer.OtpExp, a.config.Sms.OtpExp
	confirmation := otpCandidate{models.ConfirmationToken, user.ConfirmationToken, user.ConfirmationSentAt, emailExpiry}
	recovery := otpCandidate{models.RecoveryToken, user.RecoveryToken, user.RecoverySentAt, emailExpiry}
	switch params.Type {
	case mail.EmailOTPVerification:
		candidates = append(candidates, confirmation, recovery)
	case mail.SignupVerification, mail.InviteVerification:
		candidates = append(candidates, confirmation)
	case mail.RecoveryVerification, mail.MagicLinkVerification:
		candidates = append(candidates, recovery)
	case smsVerification:
		confirmation.expiry = phoneExpiry
		candidates = append(candidates, confirmation)
	case phoneChangeVerification:
		candidates = append(candidates, otpCandidate{models.PhoneChangeToken, user.PhoneChangeToken, user.PhoneChangeSentAt, phoneExpiry})
	case mail.EmailChangeVerification:
		if params.Email == "" || strings.EqualFold(params.Email, user.GetEmail()) {
			if a.config.Mailer.SecureEmailChangeEnabled {
				candidates = append(candidates, otpCandidate{models.EmailChangeTokenCurrent, user.EmailChangeTokenCurrent, user.EmailChangeSentAt, emailExpiry})
			}
		}
		if params.Email == "" || strings.EqualFold(params.Email, user.EmailChange) {
			candidates = append(candidates, otpCandidate{models.EmailChangeTokenNew, user.EmailChangeTokenNew, user.EmailChangeSentAt, emailExpiry})
		}
	}
	matched := false
	for _, candidate := range candidates {
		if candidate.hash == "" || candidate.sentAt == nil || isOtpExpired(candidate.sentAt, candidate.expiry) {
			continue
		}
		if valid && !isOtpValid(params.TokenHash, candidate.hash, candidate.sentAt, candidate.expiry) {
			continue
		}
		var token struct {
			ID            string     `db:"id"`
			AttemptCount  int        `db:"attempt_count"`
			InvalidatedAt *time.Time `db:"invalidated_at"`
		}
		err := tx.RawQuery(`SELECT id, COALESCE(attempt_count, 0) AS attempt_count, invalidated_at
   FROM one_time_tokens WHERE user_id = ? AND token_type = ? AND token_hash = ?`,
			user.ID, candidate.kind, candidate.hash).First(&token)
		if err != nil {
			if models.IsNotFoundError(err) {
				return otpRejected()
			}
			return apierrors.NewInternalServerError("Error checking verification attempts").WithInternalError(err)
		}
		if token.InvalidatedAt != nil || token.AttemptCount >= maxOTPVerificationAttempts {
			if valid {
				return otpRejected()
			}
			continue
		}
		matched = true
		if valid {
			continue
		}
		err = tx.RawQuery(`UPDATE one_time_tokens
   SET attempt_count = LEAST(COALESCE(attempt_count, 0) + 1, ?),
       invalidated_at = CASE WHEN COALESCE(attempt_count, 0) + 1 >= ? THEN now() ELSE invalidated_at END
   WHERE id = ?`, maxOTPVerificationAttempts, maxOTPVerificationAttempts, token.ID).Exec()
		if err != nil {
			return apierrors.NewInternalServerError("Error recording verification attempt").WithInternalError(err)
		}
		if token.AttemptCount == maxOTPVerificationAttempts-1 {
			logrus.WithField("token_type", candidate.kind.String()).Warn("OTP attempt limit reached")
		}
	}
	if !valid {
		return storage.NewCommitWithError(otpRejected())
	}
	if !matched {
		return otpRejected()
	}
	return nil
}

func sameOTPTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
