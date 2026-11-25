-- IDA BugFix SaaS schema — run only in a NEW dedicated Supabase project.
-- No service_role key is ever required in the browser.

create table if not exists public.ida_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  plan text not null default 'free' check (plan in ('free','pro','team')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.ida_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check (kind in ('github','zip','site')),
  title text not null,
  report jsonb not null,
  created_at timestamptz not null default now(),
  constraint ida_reports_payload_size check (pg_column_size(report) <= 1500000)
);
create index if not exists ida_reports_user_created_idx
  on public.ida_reports(user_id, created_at desc);

create table if not exists public.ida_licenses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  plan text not null check (plan in ('pro','team')),
  status text not null default 'inactive' check (status in ('inactive','active','past_due','cancelled')),
  provider text,
  provider_reference text,
  starts_at timestamptz,
  ends_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists ida_licenses_user_idx on public.ida_licenses(user_id, created_at desc);

alter table public.ida_profiles enable row level security;
alter table public.ida_reports enable row level security;
alter table public.ida_licenses enable row level security;

grant select, insert, update on public.ida_profiles to authenticated;
grant select, insert, delete on public.ida_reports to authenticated;
grant select on public.ida_licenses to authenticated;

drop policy if exists "profile read own" on public.ida_profiles;
create policy "profile read own" on public.ida_profiles for select to authenticated
using ((select auth.uid()) = user_id);
drop policy if exists "profile insert own" on public.ida_profiles;
create policy "profile insert own" on public.ida_profiles for insert to authenticated
with check ((select auth.uid()) = user_id);
drop policy if exists "profile update own" on public.ida_profiles;
create policy "profile update own" on public.ida_profiles for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "reports read own" on public.ida_reports;
create policy "reports read own" on public.ida_reports for select to authenticated
using ((select auth.uid()) = user_id);
drop policy if exists "reports insert own" on public.ida_reports;
create policy "reports insert own" on public.ida_reports for insert to authenticated
with check ((select auth.uid()) = user_id);
drop policy if exists "reports delete own" on public.ida_reports;
create policy "reports delete own" on public.ida_reports for delete to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "licenses read own" on public.ida_licenses;
create policy "licenses read own" on public.ida_licenses for select to authenticated
using ((select auth.uid()) = user_id);

-- Intentionally no client-side INSERT/UPDATE/DELETE policy for licenses.
-- Provision licences only from a trusted server or Supabase dashboard.
