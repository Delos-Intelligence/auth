-- Explicit first-party permission. Public DCR can never enable session migration.
alter table {{ index .Options "Namespace" }}.delos_oauth_client_policies
    add column allow_session_migration boolean not null default false;
