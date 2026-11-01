# AEGIS Dashboard

Static HTML + Chart.js. Reads from Supabase via the FastAPI backend in `api/main.py`.

## Launch

```
# from the project root
uvicorn api.main:app --port 8765 --reload
```

Open http://127.0.0.1:8765/ in a browser.

The dashboard calls these endpoints (all GET, JSON):

| Endpoint | Returns |
|---|---|
| `/api/health`                              | `{ok, url}` — Supabase ping |
| `/api/runs?limit=10`                       | latest campaign rows |
| `/api/run/{run_id}/scoreboard`             | ASR per (mode, round) + blocked_by_layer breakdown |
| `/api/run/{run_id}/utility`                | completion %, false blocks, latency per mode |
| `/api/run/{run_id}/tradeoff`               | ASR vs completion per mode (the key slide) |
| `/api/improvement-curve`                   | multi-round classifier-only curve (from `data/improvement_curve.json`) |
| `/api/approvals`                           | pending owner-approval queue |
| `/api/attacks?generated_by=red_agent_v1`   | agent-generated attack library |

## Charts shown

1. **ASR per defense mode per round** — bar chart grouped by round.
2. **Utility** — completion % + false-block % per mode (dual axis).
3. **ASR vs completion tradeoff** — bubble chart. Bottom-right wins.
4. **Which guardian layer blocked** — `full_guardian` mode only.
5. **Improvement curve** — classifier-only guardian across rounds; shows both sides adapting.
6. **Pending approvals** — table.
7. **Agent-generated attacks** — table.

## Design

Basic flat colors, no gradients. One color per defense mode (red / orange / blue / green). Grid lines in light grey. Light theme.

## Repopulate the data

```
python -m scripts.run_campaign --persist --rounds 2   # scoreboard + utility
python -m scripts.improvement_curve --rounds 4 --batch 6   # the curve JSON
```

Then refresh the dashboard.
