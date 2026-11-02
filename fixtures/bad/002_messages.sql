create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid,
  body text,
  created_at timestamptz default now()
);

alter table public.messages enable row level security;

create policy "Public messages are viewable by everyone"
  on public.messages
  for select
  using (true);

create policy "Anyone can update messages"
  on public.messages
  for update
  using (true)
  with check (true);
