-- Reference query bank. The Python client in sandbox/db.py wraps these.
-- Paste into the Supabase SQL editor to inspect state during development.

-- ============================================================
-- A. Attack library
-- ============================================================

-- All training-split attacks (what the guardian is allowed to learn from)
select attack_id, family, goal, generated_by, is_seed
from public.attacks
where split = 'train'
order by family, created_at;

-- Held-out families (never used for training)
select distinct family
from public.attacks
where split = 'heldout';

-- Attacks the red-team agent has generated (excludes demo seed)
select attack_id, family, goal, round, parent_attack_id, created_at
from public.attacks
where is_seed = false
order by round desc, created_at desc;

-- ============================================================
-- B. Scoreboard
-- ============================================================

-- Attack success rate per defense mode per round
select
    defense_mode,
    round,
    count(*)                        as attempts,
    sum(case when success then 1 else 0 end) as successes,
    round(100.0 * sum(case when success then 1 else 0 end) / nullif(count(*),0), 1) as asr_pct
from public.scoreboard
group by defense_mode, round
order by round, defense_mode;

-- Which guardian layer blocked the most attacks (full_guardian mode)
select blocked_layer, count(*) as blocks
from public.scoreboard
where defense_mode = 'full_guardian' and not success
group by blocked_layer
order by blocks desc;

-- Attacks that still beat full_guardian (the honest "gap" list)
select a.attack_id, a.family, a.goal, s.round
from public.scoreboard s
join public.attacks a on a.attack_id = s.attack_id
where s.defense_mode = 'full_guardian' and s.success
order by s.round desc;

-- ============================================================
-- C. Utility (M4)
-- ============================================================

-- Legit task completion rate per defense mode
select
    defense_mode,
    count(*)                                             as tasks,
    sum(case when completed then 1 else 0 end)           as completed,
    round(100.0 * sum(case when completed then 1 else 0 end) / nullif(count(*),0), 1) as completion_pct,
    sum(false_blocks)                                    as total_false_blocks,
    round(avg(latency_ms), 0)                            as avg_latency_ms,
    round(avg(extra_calls), 1)                           as avg_extra_calls
from public.task_runs
group by defense_mode
order by defense_mode;

-- ASR vs utility tradeoff (one row per mode — the key slide)
with asr as (
    select defense_mode,
           round(100.0 * sum(case when success then 1 else 0 end) / nullif(count(*),0), 1) as asr_pct
    from public.scoreboard group by defense_mode
), util as (
    select defense_mode,
           round(100.0 * sum(case when completed then 1 else 0 end) / nullif(count(*),0), 1) as completion_pct
    from public.task_runs group by defense_mode
)
select a.defense_mode, a.asr_pct, u.completion_pct
from asr a left join util u using (defense_mode)
order by a.defense_mode;

-- ============================================================
-- D. Traces (live view)
-- ============================================================

-- Full trace of a specific run
select step, actor, event, tool, decision, layer, reason
from public.trace_events
where run_id = :run_id
order by step;

-- Just the guardian decisions for a run
select step, tool, decision, layer, reason
from public.trace_events
where run_id = :run_id and actor = 'guardian'
order by step;

-- ============================================================
-- E. Owner approval queue
-- ============================================================

-- Pending approvals (what the dashboard surfaces)
select id, run_id, step, tool, args, reason
from public.owner_approvals
where decision is null
order by id;
