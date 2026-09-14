-- Optional stable lookup key for first-party clients rolling out native OAuth.
-- Authorization and refresh still use the native UUID; legacy IDs are never
-- accepted at the native token endpoint and existing sessions are unchanged.
alter table {{ index .Options "Namespace" }}.delos_oauth_client_policies
    add column if not exists client_key text
    check (client_key is null or client_key ~ '^[A-Za-z0-9_:.-]{1,128}$');
create unique index if not exists delos_oauth_client_policy_key_idx
    on {{ index .Options "Namespace" }}.delos_oauth_client_policies (client_key)
    where client_key is not null;
