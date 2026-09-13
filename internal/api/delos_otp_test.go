package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (ts *VerifyTestSuite) delosOTP(kind models.OneTimeTokenType, phone bool, code string) *models.User {
	ts.T().Helper()
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	now := time.Now().UTC()
	identity := user.GetEmail()
	if phone {
		identity = user.GetPhone()
	}
	hash := crypto.GenerateTokenHash(identity, code)
	switch kind {
	case models.ConfirmationToken:
		user.ConfirmationToken, user.ConfirmationSentAt = hash, &now
	case models.RecoveryToken:
		user.RecoveryToken, user.RecoverySentAt = hash, &now
	case models.PhoneChangeToken:
		user.PhoneChange = "12345678901"
		identity = user.PhoneChange
		hash = crypto.GenerateTokenHash(identity, code)
		user.PhoneChangeToken, user.PhoneChangeSentAt = hash, &now
	case models.EmailChangeTokenNew:
		user.EmailChange = "new@example.com"
		identity = user.EmailChange
		hash = crypto.GenerateTokenHash(identity, code)
		user.EmailChangeTokenNew, user.EmailChangeSentAt = hash, &now
	case models.EmailChangeTokenCurrent:
		user.EmailChange = "new@example.com"
		user.EmailChangeTokenCurrent, user.EmailChangeSentAt = hash, &now
	}
	require.NoError(ts.T(), ts.API.db.Transaction(func(tx *storage.Connection) error {
		if err := tx.Update(user); err != nil {
			return err
		}
		return models.CreateOneTimeToken(tx, user.ID, identity, hash, kind)
	}))
	return user
}

func (ts *VerifyTestSuite) delosVerify(body map[string]string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(response, req)
	return response
}

func (ts *VerifyTestSuite) TestDelosOTPFailuresPersistAndReplacementResets() {
	cases := []struct {
		name, verification, field, identity string
		kind                                models.OneTimeTokenType
		phone                               bool
	}{
		{"signup", "signup", "email", "test@example.com", models.ConfirmationToken, false},
		{"email signup", "email", "email", "test@example.com", models.ConfirmationToken, false},
		{"recovery", "recovery", "email", "test@example.com", models.RecoveryToken, false},
		{"email login", "email", "email", "test@example.com", models.RecoveryToken, false},
		{"sms", "sms", "phone", "12345678", models.ConfirmationToken, true},
		{"phone change", "phone_change", "phone", "12345678901", models.PhoneChangeToken, true},
		{"new email", "email_change", "email", "new@example.com", models.EmailChangeTokenNew, false},
		{"current email", "email_change", "email", "test@example.com", models.EmailChangeTokenCurrent, false},
	}
	for _, c := range cases {
		ts.Run(c.name, func() {
			ts.SetupTest()
			ts.Config.Mailer.SecureEmailChangeEnabled = true
			user := ts.delosOTP(c.kind, c.phone, "123456")
			for attempt := 1; attempt <= 3; attempt++ {
				response := ts.delosVerify(map[string]string{"type": c.verification, c.field: c.identity, "token": "000000"})
				require.Equal(ts.T(), http.StatusForbidden, response.Code, response.Body.String())
				var counter struct {
					Count int `db:"attempt_count"`
				}
				require.NoError(ts.T(), ts.API.db.RawQuery("SELECT attempt_count FROM one_time_tokens WHERE user_id = ? AND token_type = ?", user.ID, c.kind).First(&counter))
				require.Equal(ts.T(), attempt, counter.Count)
			}
			blocked := ts.delosVerify(map[string]string{"type": c.verification, c.field: c.identity, "token": "123456"})
			require.Equal(ts.T(), http.StatusForbidden, blocked.Code, blocked.Body.String())
			var sessions struct {
				Count int `db:"count"`
			}
			require.NoError(ts.T(), ts.API.db.RawQuery("SELECT count(*) FROM sessions WHERE user_id = ?", user.ID).First(&sessions))
			require.Zero(ts.T(), sessions.Count)
			ts.delosOTP(c.kind, c.phone, "654321")
			accepted := ts.delosVerify(map[string]string{"type": c.verification, c.field: c.identity, "token": "654321"})
			require.Equal(ts.T(), http.StatusOK, accepted.Code, accepted.Body.String())
		})
	}
}

func (ts *VerifyTestSuite) TestDelosOTPConcurrentFailuresAreBounded() {
	user := ts.delosOTP(models.RecoveryToken, false, "123456")
	const requests = 12
	responses := make(chan *httptest.ResponseRecorder, requests)
	var group sync.WaitGroup
	for i := 0; i < requests; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			responses <- ts.delosVerify(map[string]string{"type": "recovery", "email": "test@example.com", "token": "000000"})
		}()
	}
	group.Wait()
	close(responses)
	for response := range responses {
		require.Equal(ts.T(), http.StatusForbidden, response.Code, response.Body.String())
	}
	var state struct {
		Count         int        `db:"attempt_count"`
		InvalidatedAt *time.Time `db:"invalidated_at"`
	}
	require.NoError(ts.T(), ts.API.db.RawQuery("SELECT attempt_count, invalidated_at FROM one_time_tokens WHERE user_id = ?", user.ID).First(&state))
	require.Equal(ts.T(), 3, state.Count)
	require.NotNil(ts.T(), state.InvalidatedAt)
}

func (ts *VerifyTestSuite) TestDelosOTPConcurrentSuccessIssuesOneSession() {
	ts.delosOTP(models.RecoveryToken, false, "123456")
	const requests = 6
	responses := make(chan *httptest.ResponseRecorder, requests)
	var group sync.WaitGroup
	for i := 0; i < requests; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			responses <- ts.delosVerify(map[string]string{"type": "recovery", "email": "test@example.com", "token": "123456"})
		}()
	}
	group.Wait()
	close(responses)
	successes := 0
	for response := range responses {
		if response.Code == http.StatusOK {
			successes++
		} else {
			require.Equal(ts.T(), http.StatusForbidden, response.Code, response.Body.String())
		}
	}
	require.Equal(ts.T(), 1, successes)
}

func (ts *VerifyTestSuite) TestDelosOTPInvalidationAlsoRejectsTokenHash() {
	user := ts.delosOTP(models.RecoveryToken, false, "123456")
	require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE one_time_tokens SET attempt_count=3, invalidated_at=now() WHERE user_id=?", user.ID).Exec())
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var response *httptest.ResponseRecorder
		if method == http.MethodGet {
			req := httptest.NewRequest(method, fmt.Sprintf("/verify?type=recovery&token=%s", user.RecoveryToken), nil)
			response = httptest.NewRecorder()
			ts.API.handler.ServeHTTP(response, req)
			require.Contains(ts.T(), response.Header().Get("Location"), "otp_expired")
		} else {
			response = ts.delosVerify(map[string]string{"type": "recovery", "token_hash": user.RecoveryToken})
			require.Equal(ts.T(), http.StatusForbidden, response.Code, response.Body.String())
		}
	}
}

func (ts *VerifyTestSuite) TestDelosOTPStaleGenerationDoesNotChargeReplacement() {
	oldUser := ts.delosOTP(models.RecoveryToken, false, "123456")
	user := ts.delosOTP(models.RecoveryToken, false, "654321")
	err := ts.API.db.Transaction(func(tx *storage.Connection) error { return lockOTPUser(tx, oldUser) })
	require.Error(ts.T(), err)
	var counter struct {
		Count int `db:"attempt_count"`
	}
	require.NoError(ts.T(), ts.API.db.RawQuery("SELECT attempt_count FROM one_time_tokens WHERE user_id=?", user.ID).First(&counter))
	require.Zero(ts.T(), counter.Count)
}

func (ts *VerifyTestSuite) TestDelosRecoveryAMRAndTokenHeaders() {
	ts.delosOTP(models.RecoveryToken, false, "123456")
	response := ts.delosVerify(map[string]string{"type": "recovery", "email": "test@example.com", "token": "123456"})
	require.Equal(ts.T(), http.StatusOK, response.Code, response.Body.String())
	require.Contains(ts.T(), response.Header().Get("Cache-Control"), "no-store")
	require.Equal(ts.T(), "no-cache", response.Header().Get("Pragma"))
	var body AccessTokenResponse
	require.NoError(ts.T(), json.Unmarshal(response.Body.Bytes(), &body))
	var method struct {
		Method string `db:"authentication_method"`
	}
	require.NoError(ts.T(), ts.API.db.RawQuery("SELECT authentication_method FROM mfa_amr_claims LIMIT 1").First(&method))
	require.Equal(ts.T(), "recovery", method.Method)
}

func TestDelosPasswordRecoveryPolicy(t *testing.T) {
	require.False(t, isPasswordRecoverySession(nil))
	for _, method := range []models.AuthenticationMethod{models.OTP, models.MagicLink, models.PasswordGrant, models.Recovery} {
		t.Run(method.String(), func(t *testing.T) {
			methodName := method.String()
			session := &models.Session{AMRClaims: []models.AMRClaim{{AuthenticationMethod: &methodName}}}
			require.Equal(t, method == models.Recovery, isPasswordRecoverySession(session))
		})
	}
	require.Equal(t, models.Recovery, verificationAuthMethod("recovery"))
	require.Equal(t, models.OTP, verificationAuthMethod("email"))
}

func (ts *VerifyTestSuite) TestDelosOTPDatabaseErrorsFailClosed() {
	user := ts.delosOTP(models.RecoveryToken, false, "123456")
	err := ts.API.db.Transaction(func(tx *storage.Connection) error {
		if err := tx.RawQuery("SET LOCAL search_path = pg_catalog").Exec(); err != nil {
			return err
		}
		return ts.API.checkOTPAttempts(tx, user, &VerifyParams{Type: "recovery", TokenHash: user.RecoveryToken}, true)
	})
	var httpError *apierrors.HTTPError
	require.ErrorAs(ts.T(), err, &httpError)
	require.Equal(ts.T(), http.StatusInternalServerError, httpError.HTTPStatus)
	var state struct {
		Count int `db:"attempt_count"`
	}
	require.NoError(ts.T(), ts.API.db.RawQuery("SELECT attempt_count FROM one_time_tokens WHERE user_id=?", user.ID).First(&state))
	require.Zero(ts.T(), state.Count)
}

func (ts *VerifyTestSuite) TestDelosEmailOTPChargesBothActiveCandidates() {
	ts.delosOTP(models.ConfirmationToken, false, "111111")
	user := ts.delosOTP(models.RecoveryToken, false, "222222")
	response := ts.delosVerify(map[string]string{"type": "email", "email": "test@example.com", "token": "000000"})
	require.Equal(ts.T(), http.StatusForbidden, response.Code)
	var state struct {
		Count int `db:"count"`
	}
	require.NoError(ts.T(), ts.API.db.RawQuery("SELECT count(*) FROM one_time_tokens WHERE user_id=? AND attempt_count=1", user.ID).First(&state))
	require.Equal(ts.T(), 2, state.Count)
	response = ts.delosVerify(map[string]string{"type": "email", "email": "test@example.com", "token": "222222"})
	require.Equal(ts.T(), http.StatusOK, response.Code, response.Body.String())
}

func (ts *VerifyTestSuite) TestDelosOTPResendingSameCodeChangesGeneration() {
	oldUser := ts.delosOTP(models.RecoveryToken, false, "123456")
	ts.delosOTP(models.RecoveryToken, false, "123456")
	err := ts.API.db.Transaction(func(tx *storage.Connection) error { return lockOTPUser(tx, oldUser) })
	require.Error(ts.T(), err)
}
