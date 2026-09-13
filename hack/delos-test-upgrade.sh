#!/usr/bin/env bash
# Local/CI fixture only. Never point this at a deployed Supabase database.
set -euo pipefail
: "${DELOS_TEST_POSTGRES_URL:?Supply the local postgres admin URL}"
: "${DELOS_TEST_AUTH_URL:?Supply the local delos_auth_upgrade_test URL}"
for database_url in "$DELOS_TEST_POSTGRES_URL" "$DELOS_TEST_AUTH_URL"; do
  if [[ ! "$database_url" =~ ^postgres(ql)?://[^/@]+@(localhost|127\.0\.0\.1):[0-9]+/(postgres|delos_auth_upgrade_test)$ ]]; then
    echo 'Only loopback test database URLs are accepted' >&2
    exit 1
  fi
done
if [[ "$DELOS_TEST_AUTH_URL" != */delos_auth_upgrade_test ]]; then
  echo 'Auth URL must use delos_auth_upgrade_test' >&2
  exit 1
fi
fixture_dir=$(mktemp -d "${DELOS_TEST_TMPDIR:-/tmp}/delos-auth-upgrade.XXXXXXXX")
trap 'rm -rf -- "$fixture_dir"' EXIT
# Fail if the fixture database already exists; never reset an existing database.
psql "$DELOS_TEST_POSTGRES_URL" -v ON_ERROR_STOP=1 -c 'CREATE DATABASE delos_auth_upgrade_test OWNER supabase_auth_admin'
psql "$DELOS_TEST_AUTH_URL" -v ON_ERROR_STOP=1 -c 'CREATE SCHEMA auth AUTHORIZATION supabase_auth_admin'
git archive v2.183.2-delos migrations | tar -x -C "$fixture_dir"
GOTRUE_DB_DATABASE_URL="$DELOS_TEST_AUTH_URL" GOTRUE_DB_MIGRATIONS_PATH="$fixture_dir/migrations" \
  "${DELOS_TEST_AUTH_BINARY:-./auth}" migrate -c hack/test.env
psql "$DELOS_TEST_AUTH_URL" -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO auth.users(id, aud, role, email, confirmation_token, confirmation_sent_at)
VALUES ('00000000-0000-4000-8000-000000000196', 'authenticated', 'authenticated', 'upgrade@example.test', 'fixture-hash', now());
INSERT INTO auth.one_time_tokens(id, user_id, token_type, token_hash, relates_to, attempt_count, invalidated_at)
VALUES ('00000000-0000-4000-8000-000000000197', '00000000-0000-4000-8000-000000000196', 'confirmation_token', 'fixture-hash', 'upgrade@example.test', 3, now());
INSERT INTO auth.sessions(id, user_id, created_at, updated_at)
VALUES ('00000000-0000-4000-8000-000000000198', '00000000-0000-4000-8000-000000000196', now(), now());
SQL
GOTRUE_DB_DATABASE_URL="$DELOS_TEST_AUTH_URL" GOTRUE_DB_MIGRATIONS_PATH="$PWD/migrations" \
  "${DELOS_TEST_AUTH_BINARY:-./auth}" migrate -c hack/test.env
psql "$DELOS_TEST_AUTH_URL" -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM auth.one_time_tokens WHERE id='00000000-0000-4000-8000-000000000197' AND attempt_count=3 AND invalidated_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Legacy OTP attempt state was not preserved';
 END IF;
 IF NOT EXISTS (SELECT FROM auth.sessions WHERE id='00000000-0000-4000-8000-000000000198') THEN
  RAISE EXCEPTION 'Legacy session was not preserved';
 END IF;
 IF NOT EXISTS (SELECT FROM auth.schema_migrations WHERE version='20251203120046') THEN
  RAISE EXCEPTION 'Legacy migration record was not preserved';
 END IF;
END $$;
SQL
# A second migration run must also succeed without changing legacy state.
GOTRUE_DB_DATABASE_URL="$DELOS_TEST_AUTH_URL" GOTRUE_DB_MIGRATIONS_PATH="$PWD/migrations" \
  "${DELOS_TEST_AUTH_BINARY:-./auth}" migrate -c hack/test.env
echo 'Old Delos schema upgraded; OTP state and session preserved; migrations idempotent.'
