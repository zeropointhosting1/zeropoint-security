-- Zeropoint Security: storage for the collector's threat snapshots.
-- Run once in the Supabase dashboard: SQL Editor → New query → paste → Run.
-- Before running, replace CHANGE_ME with a long random password (keep it; it goes in the server's env file).

-- One row per file the site serves: 'threats' (full payload) and 'alerts' (live alerts only).
-- json (not jsonb) keeps the collector's text as-is, so the Worker can pass it through without parsing.
create table if not exists public.snapshots (
  name text primary key check (name in ('threats', 'alerts')),
  payload json not null,
  updated_at timestamptz not null default now()
);

alter table public.snapshots enable row level security;

-- The site (publishable/anon key) may only read. Anon and authenticated get no write grants at all.
revoke all on public.snapshots from anon, authenticated;
grant select on public.snapshots to anon;
drop policy if exists "public read" on public.snapshots;
create policy "public read" on public.snapshots for select to anon using (true);

-- Returns the stored JSON unwrapped, so /rest/v1/rpc/get_snapshot?name=threats is the file itself.
create or replace function public.get_snapshot(name text)
returns json
language sql
stable
security invoker
set search_path = ''
as $$
  select s.payload from public.snapshots s where s.name = get_snapshot.name;
$$;
revoke execute on function public.get_snapshot(text) from public;
grant execute on function public.get_snapshot(text) to anon;

-- The collector's own login: it can upsert these two rows and nothing else in the project.
-- No service_role key ever goes on the server.
do $$
begin
  if not exists (select from pg_roles where rolname = 'zeropoint_collector') then
    create role zeropoint_collector login password 'CHANGE_ME' noinherit;
  end if;
end $$;
grant usage on schema public to zeropoint_collector;
grant select, insert, update on public.snapshots to zeropoint_collector;
drop policy if exists "collector writes" on public.snapshots;
create policy "collector writes" on public.snapshots for all to zeropoint_collector
  using (true) with check (true);
