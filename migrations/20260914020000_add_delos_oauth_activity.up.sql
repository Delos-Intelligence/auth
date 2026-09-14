-- Aggregate protocol activity survives token rotation, revocation and cleanup.
-- This is operational evidence, not an authorization source.
create table {{ index .Options "Namespace" }}.delos_oauth_activity (
    bucket timestamptz not null,
    protocol text not null check (protocol in ('legacy', 'native')),
    client_key text not null check (length(client_key) between 1 and 128),
    event text not null check (event in ('signin', 'refresh')),
    outcome text not null check (outcome in ('success', 'error')),
    count bigint not null default 1,
    last_seen_at timestamptz not null default now(),
    primary key (bucket, protocol, client_key, event, outcome)
);
create table {{ index .Options "Namespace" }}.delos_oauth_legacy_sessions (
    session_id uuid primary key references {{ index .Options "Namespace" }}.sessions(id) on delete cascade,
    client_key text not null check (length(client_key) between 1 and 128),
    linked_at timestamptz not null default now()
);
create table {{ index .Options "Namespace" }}.delos_oauth_observation (
    singleton boolean primary key default true check (singleton),
    started_at timestamptz not null default now()
);
insert into {{ index .Options "Namespace" }}.delos_oauth_observation default values;
alter table {{ index .Options "Namespace" }}.delos_oauth_activity enable row level security;
alter table {{ index .Options "Namespace" }}.delos_oauth_legacy_sessions enable row level security;
alter table {{ index .Options "Namespace" }}.delos_oauth_observation enable row level security;
revoke all on {{ index .Options "Namespace" }}.delos_oauth_activity from public;
revoke all on {{ index .Options "Namespace" }}.delos_oauth_legacy_sessions from public;
revoke all on {{ index .Options "Namespace" }}.delos_oauth_observation from public;
