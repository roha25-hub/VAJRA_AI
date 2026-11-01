# VAJRA AI — Red Team vs Blue Guardian for AI Agents

A sandboxed AI employee (target agent), an attacker agent that tries to hijack it (red team), and a 5-layer guardian that defends it (blue team), with a dashboard + Live Flow page that stream real-time decisions over SSE.

Built on free resources: Gemini + Groq (LLM), Supabase (Postgres), Twilio + ElevenLabs (alerts), FastAPI + Chart.js.

## What VAJRA proves

- **M1** Target AI employee with 7 tools across email, browser/files, mock payment.
- **M2** Red-team agent that discovers successful attacks on its own (persisted to `data/m2_proof.json`).
- **M3** Guardian with 5 layers (policy → taint → classifier → LLM intent → owner approval); 15/15 fresh LLM-mutated attacks blocked across adaptive rounds.
- **M4** 100% utility on 30+ legit tasks, 0 false blocks, <10ms guardian latency.

## Quick start (local)

```bash
pip install -r requirements.txt
cp .env.example .env    # then fill in keys
uvicorn api.main:app --host 127.0.0.1 --port 8765 --no-access-log
# open http://127.0.0.1:8765
```

Pages:
- `/` — Dashboard (KPIs, charts, scoreboard, approvals)
- `/live.html` — Live Flow (SSE stream of one attack through the pipeline)
- `/notifications.html` — Alert history

Scripts:
- `python -m scripts.run_campaign_llm --target naive --fresh-attacks --num-tasks 10` — full M2+M3+M4 campaign
- `python -m scripts.rl_loop --rounds 3` — reinforcement-learning loop (every won attack is persisted and the classifier retrains)

## Architecture (one line)

```
owner task → target agent → GUARDIAN PROXY (5 layers) → mock tools → GUARDIAN PROXY → target agent
```

See [CLAUDE.md](CLAUDE.md) for the full rulebook.

## Deploy (free)

- **Backend + dashboard**: Render.com free tier (`render.yaml` included → one-click Blueprint deploy)
- **DB**: Supabase free tier (already configured via env vars)
- **LLM**: Gemini + Groq free tiers (already configured via env vars)
- **Alerts**: Twilio trial + ElevenLabs free (optional)

Set every secret through the Render dashboard; never commit `.env`.
