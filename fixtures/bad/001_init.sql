-- Demo app schema with common vibe-coding RLS mistakes.
-- Not a real client. Safe to commit.

create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  email text,
  full_name text,
  created_at timestamptz default now()
);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id),
  total_cents integer not null,
  status text default 'pending'
);

-- RLS never enabled on profiles → anyone with the anon key can read/write.

alter table public.orders enable row level security;

-- Classic Lovable/Bolt mistake: "enable read for all"
create policy "Enable read access for all users"
  on public.orders
  for select
  to anon, authenticated
  using (true);

create policy "Enable insert for all users"
  on public.orders
  for insert
  to anon, authenticated
  with check (true);

-- Public storage bucket (avatars readable by the world)
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true);
