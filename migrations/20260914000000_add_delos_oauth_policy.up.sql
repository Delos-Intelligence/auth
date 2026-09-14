-- Additive Delos OAuth policy. No existing sessions/clients are rewritten.
-- The feature remains disabled until the application data plane is ready.
create table if not exists {{ index .Options "Namespace" }}.delos_oauth_scopes (
    name text primary key check (name ~ '^[A-Za-z0-9_:.-]{1,128}$'),
    description text not null default '',
    enabled boolean not null default true
);
create table if not exists {{ index .Options "Namespace" }}.delos_oauth_client_policies (
    client_id uuid primary key references {{ index .Options "Namespace" }}.oauth_clients(id) on delete cascade,
    allowed_scopes text not null check (char_length(allowed_scopes) between 1 and 2048),
    access_mode text not null check (access_mode in ('full', 'delegated')),
    resource text not null default '',
    enabled boolean not null default true,
    check (access_mode <> 'delegated' or char_length(resource) > 0)
);
alter table {{ index .Options "Namespace" }}.delos_oauth_scopes enable row level security;
alter table {{ index .Options "Namespace" }}.delos_oauth_client_policies enable row level security;
revoke all on {{ index .Options "Namespace" }}.delos_oauth_scopes from public;
revoke all on {{ index .Options "Namespace" }}.delos_oauth_client_policies from public;
alter table {{ index .Options "Namespace" }}.sessions
    add column if not exists delos_access_mode text,
    add column if not exists delos_resource text;

alter table {{ index .Options "Namespace" }}.delos_oauth_client_policies
    add column if not exists require_aal2 boolean not null default false;
alter table {{ index .Options "Namespace" }}.oauth_authorizations
    add column if not exists delos_source_session_id uuid references {{ index .Options "Namespace" }}.sessions(id) on delete set null,
    add column if not exists delos_source_aal text;
