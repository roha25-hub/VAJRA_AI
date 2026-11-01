-- AEGIS / CYBER-02 Supabase schema.
-- Run this once in the Supabase SQL editor on a fresh project.
-- All tables are in the public schema; RLS is enabled with service-role-only
-- access by default. Open up anon reads later if the dashboard needs them.

-- =========================================================================
-- 1. attacks: the attack library (seed + agent-generated)
-- =========================================================================
create table if not exists public.attacks (
    attack_id         text primary key,
    family            text not null,
    goal              text not null,
    payload           text not null,
    injection_point   text not null,
    parent_attack_id  text references public.attacks(attack_id) on delete set null,
    generated_by      text not null,            -- 'demo_seed' | 'red_agent_v1' | ...
    is_seed           boolean not null default false,
    round             integer not null default 0,
    split             text not null default 'train',  -- 'train' | 'heldout'
    results           jsonb not null default '{}'::jsonb,
    notes             text,
    created_at        timestamptz not null default now()
);

create index if not exists attacks_family_idx on public.attacks(family);
create index if not exists attacks_split_idx  on public.attacks(split);
create index if not exists attacks_is_seed_idx on public.attacks(is_seed);

-- =========================================================================
-- 2. runs: one row per evaluation / demo run
-- =========================================================================
create table if not exists public.runs (
    run_id          text primary key,
    mode            text not null,             -- 'live' | 'replay'
    defense_mode    text not null,             -- no_defense | keyword_filter | llm_only | full_guardian
    config          jsonb not null default '{}'::jsonb,
    started_at      timestamptz not null default now(),
    finished_at     timestamptz
);

-- =========================================================================
-- 3. trace_events: every step of every run (plan §8 schema)
-- =========================================================================
create table if not exists public.trace_events (
    id          bigserial primary key,
    run_id      text not null references public.runs(run_id) on delete cascade,
    step        integer not null,
    ts          timestamptz not null default now(),
    actor       text not null,                 -- target | guardian | tool | judge
    event       text not null,                 -- tool_call | decision | tool_result | verdict
    tool        text,
    args        jsonb,
    trust       jsonb,                         -- array of taint tags
    decision    text,                          -- allow | block | escalate
    layer       text,                          -- policy | taint | classifier | intent | approval
    reason      text
);

create index if not exists trace_run_step_idx on public.trace_events(run_id, step);
create index if not exists trace_actor_idx    on public.trace_events(actor);

-- =========================================================================
-- 4. scoreboard: one row per (attack, defense_mode, round, trial)
-- =========================================================================
create table if not exists public.scoreboard (
    id             bigserial primary key,
    run_id         text not null references public.runs(run_id) on delete cascade,
    attack_id      text not null references public.attacks(attack_id),
    defense_mode   text not null,
    round          integer not null,
    trial          integer not null default 0,
    success        boolean not null,
    blocked_layer  text,                       -- which guardian layer blocked, if any
    created_at     timestamptz not null default now(),
    unique (run_id, attack_id, defense_mode, round, trial)
);

create index if not exists scoreboard_mode_round_idx on public.scoreboard(defense_mode, round);

-- =========================================================================
-- 5. legit_tasks: the utility benchmark (M4)
-- =========================================================================
create table if not exists public.legit_tasks (
    task_id      text primary key,
    name         text not null,
    description  text,
    spec         jsonb not null,               -- deterministic assertions
    created_at   timestamptz not null default now()
);

create table if not exists public.task_runs (
    id            bigserial primary key,
    run_id        text not null references public.runs(run_id) on delete cascade,
    task_id       text not null references public.legit_tasks(task_id),
    defense_mode  text not null,
    completed     boolean not null,
    false_blocks  integer not null default 0,
    latency_ms    integer,
    extra_calls   integer not null default 0,
    created_at    timestamptz not null default now()
);

-- =========================================================================
-- 6. owner_approvals: escalations the dashboard surfaces
-- =========================================================================
create table if not exists public.owner_approvals (
    id          bigserial primary key,
    run_id      text not null references public.runs(run_id) on delete cascade,
    step        integer not null,
    tool        text not null,
    args        jsonb not null,
    reason      text,
    decision    text,                          -- null | allow | deny
    decided_at  timestamptz
);

-- =========================================================================
-- Row-Level Security: lock everything by default.
-- Server (service role) bypasses RLS. The dashboard uses an anon read view later.
-- =========================================================================
alter table public.attacks         enable row level security;
alter table public.runs            enable row level security;
alter table public.trace_events    enable row level security;
alter table public.scoreboard      enable row level security;
alter table public.legit_tasks     enable row level security;
alter table public.task_runs       enable row level security;
alter table public.owner_approvals enable row level security;

-- Minimal read-only policy for the anon key (dashboard live view).
-- Comment these out if you want the dashboard to require auth.
create policy "anon read attacks"      on public.attacks         for select to anon using (true);
create policy "anon read runs"         on public.runs            for select to anon using (true);
create policy "anon read trace"        on public.trace_events    for select to anon using (true);
create policy "anon read scoreboard"   on public.scoreboard      for select to anon using (true);
create policy "anon read legit_tasks"  on public.legit_tasks     for select to anon using (true);
create policy "anon read task_runs"    on public.task_runs       for select to anon using (true);
create policy "anon read approvals"    on public.owner_approvals for select to anon using (true);
