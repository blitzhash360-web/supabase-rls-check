# supabase-rls-check

**Catch open Supabase tables and `USING (true)` policies before strangers do — in under 10 seconds.**

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![CI](https://img.shields.io/badge/GitHub%20Action-included-blue)](#github-action)
[![BlitzHash](https://img.shields.io/badge/Built%20by-BlitzHash-0a1628)](https://blitzhash.com)

## Quick start (3 steps)

```bash
# 1. Point it at your migrations (or a SQL dump)
npx github:blitzhash360-web/supabase-rls-check --sql ./supabase/migrations

# 2. Optionally scan the frontend for service-role leaks
npx github:blitzhash360-web/supabase-rls-check \
  --sql ./supabase/migrations \
  --frontend ./src

# 3. Fix anything marked CRITICAL / HIGH, then re-run
```

No account. No network call to your project. Never paste a **service-role** key into this tool or a public issue — it only needs your SQL files and (optionally) your frontend source.

## Example output

```text
supabase-rls-check · offline Supabase RLS audit
SQL files: 2 · frontend files: 0

CRITICAL [using_true] Policy "public messages are viewable by everyone" on "public.messages" uses USING (true) — anyone who can hit the API can read/write matching rows
       source: fixtures/bad/002_messages.sql
       fix: Rewrite the policy to compare a column to auth.uid() (or your tenant id). Deny by default.

CRITICAL [using_true] Policy "anyone can update messages" on "public.messages" uses USING (true) and WITH CHECK (true) — anyone who can hit the API can read/write matching rows
       source: fixtures/bad/002_messages.sql
       fix: Rewrite the policy to compare a column to auth.uid() (or your tenant id). Deny by default.

CRITICAL [using_true] Policy "enable read access for all users" on "public.orders" uses USING (true) — anyone who can hit the API can read/write matching rows
       source: fixtures/bad/001_init.sql
       fix: Rewrite the policy to compare a column to auth.uid() (or your tenant id). Deny by default.

CRITICAL [using_true] Policy "enable insert for all users" on "public.orders" uses WITH CHECK (true) — anyone who can hit the API can read/write matching rows
       source: fixtures/bad/001_init.sql
       fix: Rewrite the policy to compare a column to auth.uid() (or your tenant id). Deny by default.

CRITICAL [rls_disabled] Table "public.profiles" is created but RLS is never enabled
       source: fixtures/bad/001_init.sql
       fix: Run: alter table public.profiles enable row level security; then add policies that check auth.uid().

HIGH [public_storage_bucket] Public storage bucket detected (insert)
       source: fixtures/bad/001_init.sql
       fix: Keep buckets private and serve files through signed URLs, or restrict with storage RLS policies.

Summary: 5 critical, 1 high (6 total)

Built by BlitzHash · https://blitzhash.com · never paste a service-role key into a public issue
```

Exit code `1` when findings meet `--fail-on` (default: `high`) — ready for CI.

## What it checks

| Check | Severity | Why it matters |
|---|---|---|
| Table created without `ENABLE ROW LEVEL SECURITY` | critical | With the Data API on, the anon key can read/write the whole table |
| `USING (true)` / `WITH CHECK (true)` policies | critical | RLS is "on" but every row is still public to whoever can call the API |
| `storage.buckets` marked `public = true` | high | Anyone with the URL can download the files |
| `service_role` JWT or `NEXT_PUBLIC_*SERVICE_ROLE*` in frontend / `.env*` | critical | The service role bypasses RLS entirely — it must never ship to the browser |

## Why this matters (plain English)

If you built with Lovable, Bolt, Cursor, v0, or Replit + Supabase, the preview can look perfect while your `orders` or `messages` table is wide open. AI scaffolds often suggest **"Enable read access for all users"** with `using (true)`. That turns Row Level Security into a decorative lock: the badge says secure, the door is open.

This checker reads your SQL migrations (or a dump) offline and lists the exact policies and tables to fix. Pair it with an **Empty-Account Test**: open the app in a private window with a brand-new user and confirm you cannot see anyone else's rows.

## GitHub Action

Copy the workflow from [`.github/workflows/rls-check.yml`](.github/workflows/rls-check.yml), or use the composite action:

```yaml
- uses: blitzhash360-web/supabase-rls-check@main
  with:
    sql: supabase/migrations
    frontend: src
    fail-on: high
```

## Options

```text
--sql, -s <path>       SQL dump or migrations folder (repeatable)
--frontend, -f <path>  Frontend / env tree to scan (repeatable)
--json                 JSON report
--fail-on <level>      critical|high|medium|low (default: high)
--no-color             Disable ANSI colors
```

## Develop / test

```bash
git clone https://github.com/blitzhash360-web/supabase-rls-check
cd supabase-rls-check
npm test
node bin/supabase-rls-check.js --sql fixtures/bad --frontend fixtures/frontend
```

Fixtures under `fixtures/bad` and `fixtures/good` are intentional demo schemas — not real client data.

## Credits

- Inspired by the Supabase docs on [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) and the community pattern of auditing `USING (true)` policies.
- Related open-source work worth knowing (we are **not** a rebrand of these): [VibeRaven](https://github.com/ohad6k/VibeRaven), [supashield](https://github.com/Rodrigotari1/supashield), [supabase-rls-checker](https://github.com/hand-dot/supabase-rls-checker) (Chrome extension). This repo is a small offline CLI + Action focused on migrations/dumps and frontend service-role leaks.

## License

MIT © BlitzHash

---

Built by BlitzHash: need a senior team to check or scale your AI-built app? Free assessment at https://blitzhash.com

Want a second pair of eyes? Book a free 15-minute launch review: https://calendly.com/blitzhash360/free-15-min-launch-review
