# Supabase setup

## One-time

1. Create a free Supabase project at https://supabase.com (free tier is enough: ~500 MB Postgres, Realtime, 50k monthly active users).
2. Copy the project URL and both keys into `.env`:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY` (used by the dashboard in the browser)
   - `SUPABASE_SERVICE_ROLE_KEY` (used by the Python harness; **never ship in frontend code**)
3. In the Supabase SQL editor, run the files in this order:
   1. `schema.sql`
   2. `seed_demo_attacks.sql`

## Verifying

Run this in the SQL editor:

```sql
select count(*) as total,
       sum(case when is_seed then 1 else 0 end) as seeds,
       sum(case when split='heldout' then 1 else 0 end) as heldout
from public.attacks;
```

Expected on a fresh seed: 12 total, 12 seeds, 4 held-out.

## About the seed attacks

They exist so you can demo the system before any LLM key is available.
Every seed row has `is_seed = true` and `generated_by = 'demo_seed'`.
The campaign harness uses this flag to:

- include seeds in demos and scoreboards,
- **exclude** them from any claim about M2 ("red team discovered an attack"),
- let real agent-generated attacks drop in later with `is_seed = false` and
  `generated_by = 'red_agent_v1'`, with no schema change.

Held-out families (`multi_step`, `obfuscation`) are never used to train the
guardian's classifier or to add rules — see `queries.sql` section A.

## Common queries

See `queries.sql`. The ones you'll use most while developing:

- scoreboard ASR per mode per round
- ASR vs utility tradeoff
- attacks that still beat `full_guardian` (the honest gap list)
