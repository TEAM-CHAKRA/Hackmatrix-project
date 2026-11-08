-- =============================================================================
-- CYBERLENS — Supabase schema for the backend repository
-- =============================================================================
-- Run this once in Supabase: Dashboard → SQL Editor → New query → paste → Run.
-- It is safe to run again (everything uses IF NOT EXISTS / CREATE OR REPLACE).
--
-- Design
--   * One table per repository area. Each row keeps the full record as JSONB
--     in `data`, plus a few real columns for lookups, uniqueness and sorting.
--     This mirrors the backend's repository contract exactly, so routes and
--     services do not change.
--   * IDs are stored lower-case in the key column (case-insensitive lookup);
--     the original spelling stays inside `data`.
--   * Row Level Security is ON with NO policies: the public anon/publishable
--     key can read or write nothing. Only the backend, using the secret
--     (service_role) key, can access these tables. Never put that key in the
--     frontend.
--   * Tables are prefixed `cl_` so they never clash with other tables you
--     already created in this project.
-- =============================================================================

-- ---------- Users ------------------------------------------------------------
create table if not exists public.cl_users (
  id          text primary key,
  email       text not null unique,          -- stored lower-case
  data        jsonb not null,                -- full user record (incl. passwordHash, role)
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- ---------- Sessions (express-session via the repository) --------------------
create table if not exists public.cl_sessions (
  sid         text primary key,
  user_id     text,
  data        jsonb not null,                -- { userId, data: "<json string>", expiresAt, createdAt }
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now()
);
create index if not exists cl_sessions_expires_at_idx on public.cl_sessions (expires_at);

-- ---------- Investigations (URL + message scans) ------------------------------
create table if not exists public.cl_investigations (
  id          text primary key,              -- lower-case INV-… id
  type        text,                          -- 'url' | 'message'
  data        jsonb not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists cl_investigations_type_idx on public.cl_investigations (type);

-- ---------- Canonical snapshots (exact string that was hashed) ---------------
create table if not exists public.cl_canonical_snapshots (
  investigation_id  text primary key,        -- lower-case id
  snapshot          text not null,           -- exact JSON string, never re-serialised
  created_at        timestamptz not null default now()
);

-- ---------- Registry (blockchain anchoring + Threat Feed) ---------------------
create table if not exists public.cl_registry_entries (
  investigation_id  text primary key,        -- lower-case INV-… or CR-… id
  report_hash       text,                    -- lower-case sha256
  data              jsonb not null,
  inserted_at       timestamptz not null default now()
);
create index if not exists cl_registry_entries_hash_idx on public.cl_registry_entries (report_hash);
create index if not exists cl_registry_entries_inserted_idx on public.cl_registry_entries (inserted_at);

-- ---------- Community reports ---------------------------------------------------
create table if not exists public.cl_community_reports (
  id            text primary key,            -- lower-case CR-… id
  submitted_at  timestamptz not null default now(),
  data          jsonb not null               -- incl. status, validation, voters
);
create index if not exists cl_community_reports_submitted_idx on public.cl_community_reports (submitted_at desc);

-- ---------- Lock everything down ------------------------------------------------
alter table public.cl_users               enable row level security;
alter table public.cl_sessions            enable row level security;
alter table public.cl_investigations      enable row level security;
alter table public.cl_canonical_snapshots enable row level security;
alter table public.cl_registry_entries    enable row level security;
alter table public.cl_community_reports   enable row level security;

revoke all on public.cl_users, public.cl_sessions, public.cl_investigations,
              public.cl_canonical_snapshots, public.cl_registry_entries,
              public.cl_community_reports
  from anon, authenticated;

-- ---------- Atomic "merge these fields" updates --------------------------------
-- The backend's update methods mean { ...existing, ...updates } (top-level merge).
-- JSONB `||` does exactly that, in one statement, so concurrent updates from the
-- scan worker never overwrite each other with stale copies. Keys listed in
-- p_remove are deleted (an update value of `undefined` in JavaScript).
create or replace function public.cl_merge_record(p_table text, p_id text, p_patch jsonb, p_remove text[] default '{}')
returns jsonb
language plpgsql
security invoker
set search_path = public
as $$
declare
  result jsonb;
begin
  if p_table = 'cl_investigations' then
    update public.cl_investigations
       set data = (data || p_patch) - p_remove,
           type = coalesce(p_patch->>'type', type),
           updated_at = now()
     where id = p_id
    returning data into result;
  elsif p_table = 'cl_registry_entries' then
    update public.cl_registry_entries
       set data = (data || p_patch) - p_remove,
           report_hash = coalesce(lower(p_patch->>'reportHash'), report_hash)
     where investigation_id = p_id
    returning data into result;
  elsif p_table = 'cl_community_reports' then
    update public.cl_community_reports
       set data = (data || p_patch) - p_remove
     where id = p_id
    returning data into result;
  elsif p_table = 'cl_users' then
    update public.cl_users
       set data = (data || (p_patch - 'id' - 'email')) - (array_remove(array_remove(p_remove, 'id'), 'email')),
           updated_at = now()
     where id = p_id
    returning data into result;
  else
    raise exception 'cl_merge_record: table % is not allowed', p_table;
  end if;
  return result;  -- NULL when no row matched
end;
$$;

-- Delete expired sessions; returns how many were removed.
create or replace function public.cl_prune_expired_sessions()
returns integer
language sql
security invoker
set search_path = public
as $$
  with gone as (
    delete from public.cl_sessions where expires_at < now() returning 1
  )
  select count(*)::integer from gone;
$$;

revoke all on function public.cl_merge_record(text, text, jsonb, text[]) from public, anon, authenticated;
revoke all on function public.cl_prune_expired_sessions() from public, anon, authenticated;
grant execute on function public.cl_merge_record(text, text, jsonb, text[]) to service_role;
grant execute on function public.cl_prune_expired_sessions() to service_role;

-- Make sure the API layer sees the new tables/functions immediately.
notify pgrst, 'reload schema';
