# Delos Auth patches: assessment before the v2.196.0 upgrade

Date: 2026-09-13. Historical assessment made before implementation.
For the implemented candidate and validation results, see [DELOS.md](DELOS.md).
The recommendations below describe the original audit, not the current worktree status.

## Evidence and scope

- Existing clone: `/home/max/Documents/Pro/Delos/Suite/auth` (Delos fork).
- Isolated worktree: `/tmp/delos-auth-v2.196.0`, branch
  `upgrade/auth-v2.196.0-delos`, currently based on unmodified upstream code.
- Target: upstream `v2.196.0`, commit
  `0204331ca41a5b49f076b6fa3dc6c0d20b996590`.
- Configured Delos image tag: `v2.183.2-delos`, source commit
  `3404780485a2beb6d8f996eef3adaaec046f2d42`.
- Its actual upstream ancestor is **v2.183.0**, commit
  `7345c01537020a4277488e1b28b51664b37f3d26`; the Delos tag number alone is
  not an upstream version inventory.
- Examined the cumulative diff: **13 commits, 14 files**, plus the corresponding
  v2.196.0 implementation/tests, current Cosmos application callers and staging
  Compose configuration. GitNexus tools are unavailable; callers were traced
  with source searches. Historical shipped mobile builds remain unverified.

[Full original diff](https://github.com/Delos-Intelligence/auth/compare/7345c01537020a4277488e1b28b51664b37f3d26...3404780485a2beb6d8f996eef3adaaec046f2d42)

The recommendations below are not a claim that staging or production exhibits
every inferred failure. Concurrency, database failure and performance findings
require reproducible tests before implementation is considered validated.

## Decisions recommended

| Patch family | Still needed? | Proposed treatment |
| --- | --- | --- |
| Require current password | Yes; implementation now exists upstream | Use upstream implementation, explicitly reconcile recovery policy and error compatibility |
| Recovery exemption/AMR | Yes, as a behavior decision | Preserve Delos's recovery-only exemption for the first upgrade; keep the necessary AMR adaptation for actual recovery flows |
| Token response anti-cache headers | Yes; missing in examined upstream response paths | Retain intent, centralize a shared token-response helper, cover native OAuth handlers too |
| OTP attempt limit | Yes; no equivalent per-token three-failure limit found upstream | Redesign and test; do not copy the current helper unchanged |
| Dummy password verification | Yes, as mitigation of a specific timing discrepancy | Retain a small isolated patch, qualify its guarantees and measure cost |
| GHCR publishing | Yes for a Delos image | Adapt to upstream build/CI, validate inputs and make publishing dependent on successful checks |
| Historical configurable timing delay and debug commits | No independent feature to retain | Do not replay obsolete intermediate commits; document stale configuration |

Native OAuth enablement, custom scopes, client migrations and the Office incident
fix are later work. None of the existing fork patches fixes the application's
magic-link session minting mechanism.

## 1. Current password and recovery: upstream is not behaviorally identical

Original intent: prevent a session holder from changing an existing password
without knowing it, while allowing someone who forgot it to complete recovery.
The staging region sets
`GOTRUE_SECURITY_UPDATE_PASSWORD_REQUIRE_CURRENT_PASSWORD=true`.

Upstream v2.196.0 already has the same configuration key and request field
`current_password`. Reapplying the original configuration/validation code would
duplicate this functionality. However:

| Case, with the setting enabled | Delos v2.183.2 | Upstream v2.196.0 |
| --- | --- | --- |
| Password session updates existing password | Current password required | Required |
| Session with explicit recovery AMR | Exempt | Exempt |
| Ordinary OTP or magic-link AMR | Not exempt | Exempt |
| User without an existing password | Nonempty current_password field required outside recovery, though no stored password can be checked | First password allowed without current_password |
| Missing current password | validation_failed | current_password_required |
| Incorrect current password | invalid_credentials | current_password_invalid |

The upstream constant for the last error is named
`ErrorCodeCurrentPasswordMismatch`; the actual API string is what callers use.

Important coupling: upstream `/verify` POST and implicit GET issue **OTP** AMR
even for recovery, while its PKCE exchange retains the flow's authentication
method. Delos changes those direct recovery paths to issue **Recovery** AMR.
Keeping only a strict recovery check and dropping Delos's AMR adaptation would
break legitimate recovery. Old sessions and recovery followed by MFA also need
coverage. Restrict the policy adaptation to password updates rather than changing
the meaning of a shared recovery predicate for unrelated consumers.

Current application callers:

- `packages/features/accounts/.../password/update-password-form.tsx` sends
  `current_password`, but its field-specific wrong-password message recognizes
  only `invalid_credentials`. Upstream's new code would fall back to the generic
  error toast. Add dual-code handling before rollout, or deliberately retain
  compatible codes in the fork until clients are ready.
- Web `password-reset-request-container.tsx` and mobile `auth-hub.tsx` verify
  codes with `type: recovery`; these need the recovery AMR behavior.
- Web signup verifies with `type: email`; mobile signup uses `type: signup`.
  They must not accidentally acquire password-reset privileges under a policy
  intended to exempt only explicit recovery.
- Upstream `internal/api/user_test.go:TestUserUpdatePasswordViaRecovery`
  explicitly expects OTP and magic-link exemptions. Any Delos policy change
  must be visible in dedicated tests and the upstream test expectations.

Recommendation: use upstream validation but preserve the intended recovery-only
rule during this upgrade. Allowing a user to set a first password is a separate
behavior change, not an incidental consequence of rebasing. Verify SAML users
and password verification hooks before deciding whether to adopt that behavior.

Sources: [upstream password update](https://github.com/supabase/auth/blob/v2.196.0/internal/api/user.go),
[recovery predicate](https://github.com/supabase/auth/blob/v2.196.0/internal/models/factor.go),
[verification](https://github.com/supabase/auth/blob/v2.196.0/internal/api/verify.go).

## 2. Token caching: keep the requirement and extend coverage

The original patch adds `sendTokenJSON` and uses it for password, refresh, PKCE,
ID-token, anonymous, signup, verification, MFA and Web3 token responses. It sets
Cache-Control and Pragma before serializing the response.

The corresponding upstream v2.196.0 API paths still call `sendJSON`.
`internal/api/shared/http.go` only serializes JSON; no equivalent token-specific
headers were found in the inspected shared/token/middleware code. The current
staging Kong configuration has no matching anti-cache header rule either.
This is a source finding, not a new HTTP measurement.

Native OAuth code and refresh exchanges in
`internal/api/oauthserver/handlers.go` call `shared.SendJSON` directly. Simply
copying the old call-site substitutions would leave these paths uncovered.

Recommendation: a token-specific helper in the shared package, usable by both
API packages. Do not globally disable caching of JWKS or discovery. Test actual
HTTP responses from every affected handler and check the gateway-served headers
on staging. Successful token responses need `Cache-Control: no-store` and
`Pragma: no-cache` under [RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1).
Also inspect implicit redirects and error responses separately; the old patch
does not establish their coverage.

## 3. OTP attempts: relevant protection, incomplete implementation

Original intent: reject an OTP after three failed attempts, persist failures
despite the enclosing verification transaction rolling back, and reset the
state on token replacement. It adds `attempt_count` and `invalidated_at` through
`20251203120046_add_otp_attempt_tracking.up.sql`.

The current implementation has several concrete source-level problems:

1. `sms` maps to `phone_confirmation_token`, which is absent from the actual
   `one_time_token_type` enum. Errors are ignored/logged, so that path cannot
   deliver the intended counter behavior against the checked schema.
2. `email` always selects the confirmation counter before verification decides
   whether the matching token is confirmation or recovery. This is wrong for
   generic email OTP login backed by a recovery token.
3. Email change can validate current or new email tokens, but the limiter only
   selects `email_change_token_current`. The initial user lookup can also fail
   before reaching the counter when the submitted token is wrong.
4. Invalidation checks and updates are separate. Updates select user/type,
   without binding to the specific token ID/hash observed during verification.
   In-flight attempts can race token replacement; a successful request can
   reset invalidation after another request reaches the limit. Reproduce these
   schedules before claiming an atomic limit.
5. `storage.Dial` opens a new database pool for each recorded attempt and closes
   it immediately. Independent persistence is necessary; opening a new pool
   per attempt is not. A replacement must also avoid pool starvation or row
   locks held by the main transaction.
6. Check errors do not block verification; recording errors only log a warning.
   That favors availability but silently weakens the attempt-limit guarantee.
   Make the failure policy explicit and observable.
7. Token-hash/GET verification uses a different path and does not consult this
   invalidation helper. A claim that the token is universally invalidated after
   three failures is therefore too broad. High-entropy link verification and
   numeric code guessing have different needs; specify their intended relation.

Upstream v2.196.0 does not include these columns or an equivalent three-failure
counter in the inspected code. Endpoint rate limiting is not the same policy.

Recommendation: retain the protection requirement but redesign the mechanism
around the concrete token generation and atomic database operations. Document
exact coverage (signup, recovery, email OTP, email changes, phone and provider-
managed SMS) and failure semantics. Prove that replacement resets the intended
counter, a stale request cannot affect a new code, failures survive rollback,
and concurrent verification respects the chosen limit.

Preserve the historical migration filename/content when carrying it forward:
existing databases may already record it as applied. Any schema corrections
belong in a new migration. Test both fresh initialization and upgrade from the
old Delos schema with existing attempt rows; do not assume image rollback is
a schema rollback.

Sources: [old verification](https://github.com/Delos-Intelligence/auth/blob/v2.183.2-delos/internal/api/verify.go),
[upstream token model](https://github.com/supabase/auth/blob/v2.196.0/internal/models/one_time_token.go),
[token schema](https://github.com/supabase/auth/blob/v2.196.0/migrations/20240427152123_add_one_time_tokens_table.up.sql).

## 4. Password timing: useful narrow mitigation

The final patch performs a bcrypt comparison when password login finds no user
or a user without a password. Without it, these paths return before expensive
password verification. The dummy hash uses cost 10, matching ordinary upstream
bcrypt generation, but upstream also understands imported Argon2 and Firebase
scrypt hashes. It is not a proof of indistinguishable response times across
accounts or all error paths (for example banned users).

No equivalent dummy comparison exists in v2.196.0's password grant handler.
Recommendation: retain the narrow mitigation, with accurate comments, unchanged
generic credential errors, and tests of both affected paths. Measure CPU and
latency under rate-limited unknown-user traffic; avoid brittle timing thresholds
in unit tests. Do not log passwords, hashes or email addresses for the audit.

The configurable delay was introduced by `836b0c00` and removed by `69aeedc2`.
The staging overlay still mentions `GOTRUE_SECURITY_TIMING_OBFUSCATION_DELAY`,
but the final fork no longer defines that feature. Record this as stale
configuration; it is not a setting to restore in the new fork.

## 5. Publishing and CI: keep Delos ownership, reconcile upstream assumptions

`delos-publish.yml` publishes amd64/arm64 images to Delos GHCR on a Delos tag or
manual dispatch. This remains useful, but the original workflow interpolates a
manual version directly into shell code, edits the Dockerfile using sed, and
does not depend on a successful test job.

Upstream v2.196.0 uses Go 1.26.5, newer pinned actions, Blacksmith runner labels
and release infrastructure targeting Supabase registries/AWS. Those are not
automatically available or appropriate for the Delos fork.

Recommendation: a documented Delos release workflow with validated version
input, explicit source revision, tests/build before publication, supported
runner labels, multiarchitecture build, and an immutable recorded image digest.
Guard upstream publication/release/dogfooding workflows against accidental use
in the fork. Keep upstream tests where applicable. Evaluate all migration paths
before publishing a staging candidate; publishing is not deployment.

## Complete commit disposition

| Original commit | Purpose | Disposition |
| --- | --- | --- |
| 836b0c00 | Password timing mitigation and optional delay | Keep only final dummy-verification intent |
| a63588d0 | Token anti-cache headers | Retain and adapt shared coverage |
| 7133f0aa | Require current password | Replace duplication with upstream plus explicit policy/compatibility delta |
| 4626701a | OTP limit and migration | Retain migration history; redesign implementation |
| 69aeedc2 | Remove configurable timing delay | Preserve final removal |
| e0eaf042 | Fix old OTP API compatibility | Historical fix; use current storage APIs |
| e72624c2 | Add diagnostic OTP logs | Do not replay temporary debugging |
| 081e6966 | Promote diagnostic logs to info | Do not replay temporary debugging |
| 91617611 | Persist OTP attempts outside rollback | Preserve persistence requirement, revise connection strategy |
| a9edb4e9 | Remove verbose logs and unused helper | Preserve cleanup, retain useful failure telemetry |
| a2607f18 | Exempt recovery sessions and issue Recovery AMR | Reconcile with upstream as one coupled policy change |
| 155bd86b | Debug-log cleanup | No independent feature; a GET recovery info log still remains in the final tag |
| 34047804 | Delos GHCR publishing | Adapt and validate release pipeline |

## Implementation and validation order

1. Record the password/recovery and OTP policies, including compatibility with
   existing clients and sessions. Add behavior tests before replacing helpers.
2. Port the anti-cache and timing changes as small independently reviewable
   commits. Reconcile upstream password behavior and application error mapping.
3. Implement the OTP mechanism with database/concurrency regression tests and
   fresh/old-schema migration tests.
4. Adapt CI/release packaging; build with the target Go version and run relevant
   upstream tests plus the Delos regressions. Then run the broader suite.
5. Prepare a pinned staging candidate and an Auth-only deployment procedure,
   including migration-aware recovery. No blanket infrastructure sync.
6. Validate password login, signup/recovery OTP, implicit and PKCE recovery,
   MFA, SAML, existing refresh sessions and representative old mobile clients
   on staging. Only after baseline compatibility should native OAuth enablement
   and custom scope extensions proceed.

No runtime test result is claimed by this document. The source audit is complete
for the 13-commit cumulative patch; the recommended replacements still require
implementation and validation.
