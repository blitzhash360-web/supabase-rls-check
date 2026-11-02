-- Hardened example: RLS on, policies scoped to auth.uid()

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text,
  created_at timestamptz default now()
);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  total_cents integer not null,
  status text default 'pending'
);

alter table public.profiles enable row level security;
alter table public.orders enable row level security;

create policy "Users read own profile"
  on public.profiles
  for select
  to authenticated
  using (auth.uid() = id);

create policy "Users update own profile"
  on public.profiles
  for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

create policy "Users read own orders"
  on public.orders
  for select
  to authenticated
  using (auth.uid() = user_id);

create policy "Users insert own orders"
  on public.orders
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Private bucket
insert into storage.buckets (id, name, public)
values ('invoices', 'invoices', false);
