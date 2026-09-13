# Delos Auth v2.196.0 candidate

This fork starts at upstream **v2.196.0** (`0204331ca41a5b49f076b6fa3dc6c0d20b996590`).
The previous configured image was `v2.183.2-delos`, source
`3404780485a2beb6d8f996eef3adaaec046f2d42`, based on upstream v2.183.0.
See [the patch audit](DELOS-PATCH-AUDIT.md) for the historical evidence.

## What remains custom

| Behavior | Implementation |
| --- | --- |
| Current password required | Upstream configuration and validation; small Delos recovery-policy and error-code adaptations |
| Explicit recovery exemption | Recovery AMR retained for direct OTP/implicit recovery; upstream PKCE recovery retained |
| Token caching | Shared token-response headers, including native OAuth exchange and refresh; token/verify entry points also mark redirects and errors non-cacheable |
| Unknown-user password timing | Dummy bcrypt comparison retained as a narrow mitigation, not a constant-time guarantee |
| Three incorrect OTP attempts | Transactional counter tied to the current token, serialized with issuance and consumption |
| Release packaging | Delos CI and GHCR workflow; upstream organization-specific jobs are guarded |

The duplicated current-password configuration implementation, configurable timing
sleep, temporary debug patches and per-request database pool are not carried
forward. The old migration file is retained byte-for-byte because databases may
already have applied it.

## OTP behavior and deliberate changes

The limiter covers locally verified signup, recovery, email OTP, SMS and phone
change codes, and each side of email changes. Generic email verification checks
both confirmation and recovery candidates: an incorrect guess charges both
active candidates; a correct code checks only the matching candidate.

Verification locks the user row before checking the token state, using the same
user-before-token order as issuance. A request that observes replacement while
waiting rejects without charging the new generation. The failed-attempt update
commits using upstream `storage.CommitWithError`; account/session changes have
not begun at that point. Valid verification and token consumption remain in the
same transaction. No new database pool is opened for an attempt.

After three failures the same code is rejected through numeric-code, token-hash
and GET link verification. A newly issued token has a fresh counter. Unlike the
old patch, database errors fail closed with a server error; they are not silently
ignored. Missing or mismatched token rows reject verification.

Provider-managed Twilio Verify and configured test SMS codes retain upstream
handling. When multiple pending users share an email-change destination, a wrong
code is rejected without selecting an arbitrary user's counter; endpoint rate
limits remain necessary. This is a per-token retry budget, not a replacement for
rate limiting or protection against targeted denial of service.

Monitor verification 5xx, database lock latency and the `OTP attempt limit reached`
warning. The warning identifies the token type, not an email or a token value.
Alerting and thresholds need staging baselines before production rollout.

## Compatibility decisions

With `GOTRUE_SECURITY_UPDATE_PASSWORD_REQUIRE_CURRENT_PASSWORD=true`, ordinary
OTP and magic-link sessions continue to require the current password; only
explicit recovery is exempt. The previous first-password field requirement is
also preserved. Upstream's broader exemption is not adopted incidentally.

The old client-facing errors (`validation_failed` for a missing current password,
`invalid_credentials` for a wrong current password) are retained so released web
and mobile clients do not need to understand new upstream error codes first.

This candidate does **not** enable the native OAuth server, implement custom
scopes, migrate OAuth clients or fix the application's magic-link session-minting
bridge. Those changes follow baseline Auth validation. Existing SAML behavior is
covered by upstream tests, but a real IdP staging test remains required.

## Local validation (2026-09-13)

- Build toolchain: Go 1.26.8. Auth stays on v2.196.0; the initial upstream
  Go 1.26.5 pin reported seven standard-library advisories, fixed in later Go
  patch releases. All five build/module pins are updated together.
  [Go release history](https://go.dev/doc/devel/release#go1.26.0).
- Full `go test ./... -p 1 -race -count=1 -timeout=20m`: **2,207 test/subtest
  passes across 39 tested packages**, no failures; 13 packages have no tests.
  The OrioleDB-specific index test is skipped on PostgreSQL.
- `go vet ./...`, upstream `staticcheck` and `gosec` (production and tests): passed.
  Gosec correctly identified the public dummy bcrypt hash as a potential
  credential; its sole annotation explains that it never authenticates a user.
- Fresh PostgreSQL 15 migration: passed.
- Old Delos SQL migration set → new migration set: passed, with an existing
  session and invalidated OTP row preserved; repeat migration passed.
  This verifies schema/data preservation, not an authenticated refresh from an
  old mobile build.
- All workflow YAML parsed with duplicate-key rejection; actionlint passed with
  the retained upstream runner labels declared in `.github/actionlint.yaml`.
- Local Docker build: passed; container reports `v2.196.0-delos.1-rc.1`.
  The image was built locally for review, not published. It cross-compiles the
  upstream binary targets; multiarchitecture image publication remains a CI step.

The regression tests cover parallel failures, single successful consumption under
concurrency, replacement (including the same code reissued), database errors,
recovery AMR, and native OAuth exchange/refresh cache headers. Two upstream
password-recovery expectations now explicitly assert Delos policy. The upstream
PKCE fixture was completed with the user token fields written by real issuance;
its expected successful flow is unchanged. Other upstream tests remain enabled.
Five upstream files also needed formatting-only changes for the standard gofmt
CI gate; their whitespace-insensitive diff is empty.

The complete suite, static checks and Docker build were rerun successfully
with Go 1.26.8. The upstream vulnerability gate passes with only its two
pre-existing exclusions listed below. No new exclusions were added.

## Inherited dependency findings

Upstream's vulnerability gate excludes two existing database-driver advisories;
this candidate does not add exclusions or claim a clean raw vulnerability scan.

- [GO-2026-5004](https://pkg.go.dev/vuln/GO-2026-5004): pgx/v4 has no published
  fix. The advisory concerns non-default simple protocol, dollar-quoted SQL
  containing placeholder-like text and an attacker-controlled parameter.
- [GO-2026-4518](https://pkg.go.dev/vuln/GO-2026-4518): pgproto3/v2 has no published
  fix. A malicious/compromised PostgreSQL server can trigger a decoder panic.

The Go vulnerability database confirms these conditions and affected branches
as of 2026-09-13.
Retaining upstream's gate is not a fresh acceptance of deployment risk. Review
our effective driver settings/query paths and the pgx/v5 migration separately
before production promotion; do not hide these findings in the release report.

## Reproducing tests

Use a disposable PostgreSQL 15 instance and the test configuration in
`hack/test.env`. The suite truncates Auth tables: never use a staging/production
URL. Follow the setup in `.github/workflows/delos-checks.yml` for a complete
local/CI sequence. The upgrade fixture script only accepts loopback URLs and
creates `delos_auth_upgrade_test`; it refuses to reset an existing fixture DB.

Useful commands after database initialization/migrations:

```sh
go test ./... -p 1 -race -count=1 -timeout=20m
go vet ./...
make -C tools
make static sec
```

Review the Delos delta independently of the upstream upgrade:

```sh
git diff v2.196.0..HEAD -- internal migrations Dockerfile .github hack DELOS.md
```

## Candidate publication and staging

`delos-publish.yml` requires successful Delos checks before publishing. It accepts
validated versions such as `2.196.0-delos.1-rc.1`, builds amd64/arm64 images and
records the source revision and registry digest. Pin deployments to that digest;
version and SHA tags alone are not a registry immutability guarantee. Upstream
publishing, release and dogfooding jobs cannot run in the Delos organization.

Before staging application:

1. Review the candidate and CI results, then publish an explicit candidate tag.
2. Prepare the Auth-only infrastructure image change with native OAuth still
   disabled. Preserve existing keys, hooks, SAML, redirect URLs and SMTP settings.
3. Take a recoverable database snapshot and record old image/configuration.
   Test a consistent database/image restore; changing the image back is not a
   proven downgrade after Auth migrations.
4. Apply only the Auth candidate to staging. The infrastructure `deploy-db.sh`
   currently performs whole-stack pull/up, so do not use an unreviewed broad
   sync for this change. Leave unrelated production changes to their owner.
5. Exercise signup, password login/update, OTP and PKCE/implicit recovery, MFA,
   SAML, existing refresh sessions and representative released mobile builds.
   Observe verification failures, lock waits and refresh errors.
6. Decide native OAuth enablement, client refresh adaptation and delegated scopes
   separately after this baseline is accepted.
