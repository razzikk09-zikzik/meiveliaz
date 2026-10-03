-- MEYVIZHI Supabase schema — paste into Supabase Dashboard → SQL Editor → New query → Run.

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  category text not null,
  message text default '',
  url text default '',
  phone text default '',
  upi_id text default '',
  location text default 'South Chennai',
  money_lost text default 'no' check (money_lost in ('no', 'almost', 'yes')),
  anonymous boolean default true,
  risk_level text default 'UNASSESSED',
  created_at timestamptz not null default now()
);

create table if not exists public.alerts (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  detail text default '',
  area text not null,
  reports int default 0,
  risk text default 'HIGH',
  created_at timestamptz not null default now()
);

create table if not exists public.analysis_results (
  id uuid primary key default gen_random_uuid(),
  report_id uuid references public.reports (id) on delete set null,
  classification text not null,
  risk_score int not null check (risk_score between 0 and 100),
  signals jsonb default '[]',
  sources jsonb default '{}',
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key,                     -- matches auth.users.id
  display_name text default '',
  role text default 'analyst' check (role in ('analyst', 'admin')),
  created_at timestamptz not null default now()
);

create index if not exists reports_created_at_idx on public.reports (created_at desc);
create index if not exists reports_location_idx on public.reports (location);
create index if not exists reports_category_idx on public.reports (category);

-- Row Level Security:
-- The backend uses the service_role key (bypasses RLS) for writes.
-- Public: read-only on alerts; anonymous inserts are done by the backend,
-- never directly from the browser.
alter table public.reports enable row level security;
alter table public.alerts enable row level security;
alter table public.analysis_results enable row level security;
alter table public.profiles enable row level security;

create policy "alerts are publicly readable" on public.alerts for select using (true);
create policy "reports readable by authenticated analysts" on public.reports for select using (auth.role() = 'authenticated');
create policy "profiles readable by owner" on public.profiles for select using (auth.uid() = id);
