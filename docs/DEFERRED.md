# Deferred work

Running list of things scaffolded or stubbed, to finish before shipping.
Each entry: what's missing, where, and what unblocks it.

## STUB implementations (code says `STUB` or `NotImplementedError`)

- [x] **`llm/gateway.py`** — httpx-based, SQLite cache, per-provider rate limit, failover, usage counters. Live-tested with Gemini + Groq.
- [x] **`sandbox/db.py`** — supabase-py wrapper with connection-retry wrapper for all writes. `run_campaign --persist` writes attacks/runs/scoreboard/task_runs/approvals.
- [ ] **Trace events not yet persisted.** `log_event`/`log_events` are implemented but the campaign doesn't emit `TraceEvent`s per step yet. Dashboard live view needs this.
- [ ] **Record/replay mode** — gateway accepts the mode flag but there's no separate replay-only store yet. Cache acts as a record for now; a true "fail if not recorded" replay path needs wiring in `Gateway.chat`.

## Phase 1 (M1) — small gaps

- [ ] **Target is scripted, not LLM-driven.** Two stand-ins exist (`agents/target.py::scripted_invoice_policy`, `agents/naive_target.py::naive_instruction_following`). Swap in gateway-backed `model_fn` once the gateway is real; keep the scripted ones for CI.
- [ ] **Traces are in-memory only.** `TraceStep` doesn't yet serialize to `trace_events` in Supabase. Will wire via `sandbox/db.py::log_event`.
- [ ] **No `send_email` in the scripted policy.** M1 says "reply to vendors with questions" — the scripted policy pays but doesn't reply to `e4`. The LLM target will do this; or extend the script.

## Attack library

- [x] **M2 autonomy satisfied.** Red-team agent (`agents/redteam.py`) produced 6/6 judge-confirmed `redirect_payment` attacks against the undefended naive target. Proof: `data/m2_proof.json`.
- [x] **Agent-generated attacks persisted to Supabase** via `run_campaign --persist`.

## Not started yet (planned)

- [ ] `judge/canary.py` + `judge/utility.py` — deterministic success rules (Phase 2, M2 baseline).
- [x] `agents/redteam.py` — attack generation, bandit over families.
- [x] `agents/guardian/` — proxy, policy, taint, classifier, intent, approvals.
- [x] **Mutation loop in red-team** — `mutate_batch()` + `scripts/improvement_curve.py` demonstrate it; retrain on train-split successes between rounds.
- [ ] **Classifier is tiny** — 8 train attacks + 10 benign messages. Will need more variety before utility measurements mean anything.
- [ ] **`llm_only` mode is weak** — the intent LLM alone passed some attack variants in M3. Expected; the full guardian is what the plan recommends. Keep as a baseline for the scoreboard.
- [x] `eval/campaign.py`, `eval/metrics.py`, `eval/tasks/` — four defense modes, 30 legit tasks, 2 rounds.
- [ ] **`llm_only` on held-out is suspiciously low (50%)** — likely because held-out families (base64, Spanish, multi-step) don't trip the naive target's regex, so some "misses" are target under-reach, not defense wins. Flag honestly on the slide and retest with an LLM target.
- [ ] **`no_defense` 100% on held-out is partly inflated** — multi_step attacks succeed via a hardcoded exfil destination in `naive_target.py`. With a real LLM target this exact path may not trigger. Note on the slide.
- [ ] **Trials fixed at 1.** Plan asks for ~3 per (attack, mode) once we can afford it. Temperature-0 + cache keeps variance low but trials are not yet measured.
- [x] `api/main.py` + `dashboard/` — FastAPI backend + static Chart.js dashboard, basic 4-color palette.
- [ ] **No WebSocket live events yet** — dashboard pulls on load/refresh. Add SSE or WS later for live trace streaming.

## Convention

When something new gets deferred, add a line here with a `[ ]` checkbox and
the blocker. When it's done, flip to `[x]` or delete the line.
