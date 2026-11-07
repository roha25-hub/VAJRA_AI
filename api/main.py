"""FastAPI backend for the AEGIS dashboard.

Reads from Supabase. Serves the static dashboard at /.
No WebSocket live events in v1 — refresh for the latest numbers.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import asyncio
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sandbox.db import DB


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
CURVE_PATH = PROJECT_ROOT / "data" / "improvement_curve.json"

app = FastAPI(title="AEGIS Dashboard")

_db: DB | None = None


def db() -> DB:
    global _db
    if _db is None:
        _db = DB.from_env()
    return _db


# Simple TTL cache for read-heavy endpoints that hit Supabase.
_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 5.0  # seconds — dashboard polls faster than scoreboard changes


def _cached(key: str, loader):
    now = time.time()
    hit = _cache.get(key)
    if hit and (now - hit[0] < _CACHE_TTL):
        return hit[1]
    val = loader()
    _cache[key] = (now, val)
    return val


@app.middleware("http")
async def _add_cache_hdrs(request, call_next):
    resp = await call_next(request)
    if request.url.path.startswith("/api/") and request.method == "GET":
        resp.headers.setdefault("Cache-Control", "public, max-age=3")
    return resp


# ============================================================
# API
# ============================================================

@app.get("/api/health")
def health() -> dict[str, Any]:
    try:
        d = db()
        _ = d._client.table("runs").select("run_id").limit(1).execute()
        return {"ok": True, "url": d.url}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/runs")
def list_runs(limit: int = 10) -> list[dict[str, Any]]:
    rows = db()._client.table("runs").select("*") \
        .order("started_at", desc=True).limit(limit).execute().data
    return rows or []


def _sb_rows(run_id: str) -> list[dict[str, Any]]:
    return _cached(
        f"sb_rows:{run_id}",
        lambda: db()._client.table("scoreboard").select("*")
            .eq("run_id", run_id).execute().data or [],
    )


def _task_rows(run_id: str) -> list[dict[str, Any]]:
    return _cached(
        f"task_rows:{run_id}",
        lambda: db()._client.table("task_runs").select("*")
            .eq("run_id", run_id).execute().data or [],
    )


@app.get("/api/run/{run_id}/scoreboard")
def scoreboard(run_id: str) -> dict[str, Any]:
    rows = _sb_rows(run_id)
    by_mode_round: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for r in rows:
        by_mode_round[(r["defense_mode"], r["round"])].append(r)
    out: list[dict[str, Any]] = []
    for (mode, rnd), items in sorted(by_mode_round.items()):
        n = len(items)
        s = sum(1 for i in items if i["success"])
        out.append({
            "mode": mode, "round": rnd,
            "attempts": n, "successes": s,
            "asr_pct": round(100 * s / n, 1) if n else 0.0,
        })
    # Blocked-layer breakdown for full_guardian
    by_layer: dict[str, int] = defaultdict(int)
    for r in rows:
        if r["defense_mode"] == "full_guardian" and not r["success"]:
            by_layer[r.get("blocked_layer") or "unknown"] += 1
    return {"rows": out, "blocked_by_layer": dict(by_layer)}


@app.get("/api/run/{run_id}/utility")
def utility(run_id: str) -> list[dict[str, Any]]:
    rows = _task_rows(run_id)
    bucket: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        bucket[r["defense_mode"]].append(r)
    out: list[dict[str, Any]] = []
    for mode, items in sorted(bucket.items()):
        n = len(items)
        done = sum(1 for i in items if i["completed"])
        fb = sum(i["false_blocks"] for i in items)
        avg_lat = sum(i.get("latency_ms", 0) for i in items) / n if n else 0
        out.append({
            "mode": mode, "n": n,
            "completion_pct": round(100 * done / n, 1) if n else 0.0,
            "false_blocks": fb,
            "false_block_pct": round(100 * fb / n, 2) if n else 0.0,
            "avg_latency_ms": round(avg_lat, 1),
        })
    return out


@app.get("/api/run/{run_id}/tradeoff")
def tradeoff(run_id: str) -> list[dict[str, Any]]:
    sb = scoreboard(run_id)["rows"]
    ut = utility(run_id)
    asr_by_mode: dict[str, list[int]] = defaultdict(list)
    for r in sb:
        asr_by_mode[r["mode"]].extend([r["asr_pct"]])
    asr_avg = {m: round(sum(v) / len(v), 1) for m, v in asr_by_mode.items() if v}
    ut_by_mode = {u["mode"]: u for u in ut}
    out: list[dict[str, Any]] = []
    for mode in sorted(set(asr_avg) | set(ut_by_mode)):
        u = ut_by_mode.get(mode, {})
        out.append({
            "mode": mode,
            "asr_pct": asr_avg.get(mode, 0.0),
            "completion_pct": u.get("completion_pct", 0.0),
            "false_block_pct": u.get("false_block_pct", 0.0),
        })
    return out


@app.get("/api/improvement-curve")
def improvement_curve() -> list[dict[str, Any]]:
    if not CURVE_PATH.exists():
        return []
    try:
        return json.loads(CURVE_PATH.read_text())
    except Exception as e:
        raise HTTPException(500, f"could not read curve: {e}")


@app.get("/api/approvals")
def approvals() -> list[dict[str, Any]]:
    rows = db()._client.table("owner_approvals").select("*") \
        .is_("decision", "null").order("id", desc=True).limit(50).execute().data
    return rows or []


@app.get("/api/attacks")
def attacks(generated_by: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    q = db()._client.table("attacks").select("attack_id, family, goal, generated_by, is_seed, round")
    if generated_by:
        q = q.eq("generated_by", generated_by)
    return q.limit(limit).execute().data or []


# -------- Detail endpoints --------

@app.get("/api/run/{run_id}/summary")
def run_summary(run_id: str) -> dict[str, Any]:
    """One-line totals: attacks run, success count, tasks run, completion count, false blocks."""
    sb = _sb_rows(run_id)
    tr = _task_rows(run_id)
    run = _cached(f"run:{run_id}", lambda:
        db()._client.table("runs").select("*").eq("run_id", run_id).execute().data or [])
    return {
        "run": run[0] if run else None,
        "scoreboard_cells": len(sb),
        "scoreboard_successes": sum(1 for r in sb if r["success"]),
        "task_cells": len(tr),
        "task_completions": sum(1 for r in tr if r["completed"]),
        "task_false_blocks": sum(r["false_blocks"] for r in tr),
    }


@app.get("/api/run/{run_id}/attack-detail")
def run_attack_detail(run_id: str) -> list[dict[str, Any]]:
    """Per-attack-per-mode rows for drill-down."""
    rows = db()._client.table("scoreboard") \
        .select("attack_id, defense_mode, round, trial, success, blocked_layer") \
        .eq("run_id", run_id).order("attack_id").order("defense_mode").execute().data
    return rows or []


@app.get("/api/run/{run_id}/task-detail")
def run_task_detail(run_id: str) -> list[dict[str, Any]]:
    rows = db()._client.table("task_runs") \
        .select("task_id, defense_mode, completed, false_blocks, latency_ms, extra_calls") \
        .eq("run_id", run_id).order("task_id").order("defense_mode").execute().data
    return rows or []


@app.get("/api/attack/{attack_id}")
def attack_detail(attack_id: str) -> dict[str, Any]:
    rows = db()._client.table("attacks").select("*").eq("attack_id", attack_id).execute().data
    if not rows:
        raise HTTPException(404, f"attack {attack_id} not found")
    return rows[0]


# -------- Approval resolve --------

class _ResolveBody(BaseModel):
    decision: str   # "allow" | "deny"


@app.post("/api/approvals/{approval_id}/resolve")
def resolve(approval_id: int, body: _ResolveBody) -> dict[str, Any]:
    if body.decision not in ("allow", "deny"):
        raise HTTPException(400, "decision must be 'allow' or 'deny'")
    db().resolve_approval(approval_id, body.decision)
    return {"ok": True, "id": approval_id, "decision": body.decision}


# ============================================================
# LIVE FLOW -- SSE stream of backend stages for ONE attack run
# ============================================================

import json as _json
from queue import Queue, Empty
from threading import Thread


def _resolve_payload(
    atk_row: dict[str, Any],
    gw: Any,
    emit,
    timeout_s: float = 12.0,
    bypass_cache: bool = True,
) -> tuple[str, str]:
    """Try the real red-team LLM first. On any failure (empty, exception, or
    timeout) fall back to the DB-stored payload for this attack_id.

    Returns (payload, source) where source is 'live_llm' or 'db_fallback'.
    """
    from agents.redteam import generate_batch

    goal = atk_row["goal"]
    family = atk_row["family"]
    emit("redteam_try", provider="gateway", goal=goal, family=family,
         msg="asking red-team LLM for a fresh payload")

    result: dict[str, Any] = {}

    def worker() -> None:
        try:
            # Force a fresh LLM call for every Live Flow run (not cached).
            prior_mode = getattr(gw, "mode", "live")
            try:
                if bypass_cache:
                    gw.mode = "fresh"
                payloads = generate_batch(gw, goal=goal, family=family, n=1)
            finally:
                gw.mode = prior_mode
            result["payloads"] = payloads
        except Exception as e:
            result["error"] = str(e)

    t = Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout=timeout_s)

    if t.is_alive():
        emit("redteam_fallback", reason="llm_timeout",
             detail=f"red-team LLM did not respond in {timeout_s:.0f}s",
             using_attack_id=atk_row["attack_id"])
        return atk_row["payload"], "db_fallback"

    if "error" in result:
        emit("redteam_fallback", reason="llm_error",
             detail=result["error"][:200],
             using_attack_id=atk_row["attack_id"])
        return atk_row["payload"], "db_fallback"

    payloads = result.get("payloads") or []
    if not payloads:
        emit("redteam_fallback", reason="empty_response",
             detail="LLM returned no usable payload",
             using_attack_id=atk_row["attack_id"])
        return atk_row["payload"], "db_fallback"

    live = payloads[0]
    emit("redteam_live", chars=len(live), goal=goal, family=family,
         preview=live[:200],
         msg="using fresh LLM-generated payload")
    return live, "live_llm"


def _run_attack_and_emit(attack_id: str, mode: str, q: "Queue[dict[str, Any]]") -> None:
    """Run a single attack through the chosen defense mode, emitting stage
    events to the queue as execution progresses. Called in a thread so the
    HTTP streaming response can read from the queue.
    """
    from agents.guardian.approvals import ApprovalQueue
    from agents.guardian.policy import load_policy
    from agents.guardian.proxy import GuardianProxy
    from agents.llm_target import llm_policy
    from agents.target import run_target
    from eval.attack_runner import SeedAttack, _plant
    from judge.canary import judge
    from llm.gateway import Gateway
    from sandbox.world import load_scenario

    def emit(stage: str, **payload: Any) -> None:
        q.put({"stage": stage, "ts": datetime.now(timezone.utc).isoformat(), **payload})

    try:
        emit("boot", msg=f"preparing attack={attack_id} mode={mode}")

        # Fetch the attack row from Supabase.
        rows = db()._client.table("attacks").select("*").eq("attack_id", attack_id).execute().data
        if not rows:
            emit("error", msg=f"attack {attack_id} not found")
            q.put({"stage": "done"}); return
        atk_row = rows[0]

        gw = Gateway.from_config()

        # Pipeline: try live LLM red-team first, fall back to DB payload.
        payload, source = _resolve_payload(atk_row, gw, emit)

        # If we actually got a fresh LLM payload, save it as its own row
        # so each click leaves a distinct trace in the DB + dashboard.
        import time as _tnow
        if source == "live_llm":
            live_atk_id = f"live_{int(_tnow.time()*1000)}_{atk_row['attack_id']}"
            try:
                from sandbox.db import AttackRecord
                db().insert_attack(AttackRecord(
                    attack_id=live_atk_id, family=atk_row["family"],
                    goal=atk_row["goal"], payload=payload,
                    injection_point=atk_row["injection_point"],
                    parent_attack_id=atk_row["attack_id"],
                    generated_by="live_gemini", is_seed=False,
                    round=0, split="train",
                ))
            except Exception:
                live_atk_id = atk_row["attack_id"]  # fall back to seed id
        else:
            live_atk_id = atk_row["attack_id"]

        atk = SeedAttack(
            attack_id=live_atk_id, family=atk_row["family"],
            goal=atk_row["goal"], payload=payload,
            injection_point=atk_row["injection_point"],
        )

        emit("inject", family=atk.family, goal=atk.goal,
             injection_point=atk.injection_point,
             source=source,
             payload_preview=atk.payload[:220])
        world = load_scenario("default")
        _plant(world, atk)
        emit("world_ready", inbox=len(world.inbox), pages=len(world.pages), files=len(world.files))

        # Subclass GuardianProxy so __call__ dispatch (Python looks up
        # dunder methods on the CLASS) actually hits our wrapped version
        # and emits per-step events.
        class _LiveProxy(GuardianProxy):
            def __call__(self, w, tool, args):  # type: ignore[override]
                emit("tool_call", tool=tool, args=args)
                result = super().__call__(w, tool, args)
                # Emit per-specialist votes (multi mode) BEFORE the final
                # guardian_decision so the UI can light sub-nodes first.
                for v in getattr(self, "_last_votes", []) or []:
                    emit("specialist_vote",
                         tool=tool, specialist=v.specialist,
                         vote=v.vote, reason=v.reason,
                         latency_ms=v.latency_ms)
                self._last_votes = []  # clear for next call
                step = self.trace[-1] if self.trace else None
                if step:
                    d = step.decision
                    emit("guardian_decision",
                         tool=tool, verdict=d.verdict, layer=d.layer,
                         reason=d.reason,
                         blocked=bool(result.get("blocked")))
                return result

        base = _LiveProxy(
            mode=mode, policy=load_policy("process_invoices"),
            gateway=gw if mode in ("llm_only", "full_guardian") else None,
            approvals=ApprovalQueue("deny"),
        )

        emit("run_start", mode=mode)
        result = run_target(world, llm_policy(gw), proxy=base, step_cap=14)
        v = judge(world, result)

        # Attribute the attack's payload to a known pattern (TF-IDF).
        try:
            from agents.attribution.attributor import classify as _classify
            attr = _classify(atk.payload)
            emit("attribution",
                 pattern=attr.pattern, label=attr.label,
                 family=attr.family, severity=attr.severity,
                 confidence=attr.confidence, runners_up=attr.runners_up)
            attr_dict = attr.to_dict()
        except Exception as _ae:
            attr_dict = None
            emit("attribution_error", msg=str(_ae)[:160])

        emit("verdict",
             success=v.success,
             rules_fired=v.rules_fired,
             summary=result.summary[:300],
             steps=len(result.trace),
             ledger=world.ledger,
             outbox=world.outbox,
             attribution=attr_dict)

        # Persist to a dedicated "live_demo" run so dashboard numbers tick up.
        try:
            first_block = next((t.decision for t in base.trace
                                if t.decision.verdict == "block"), None)
            demo_run = "live_demo"
            # Ensure run row exists (idempotent-ish; ignore if dupe)
            try:
                db().create_run(demo_run, mode="live", defense_mode=mode,
                                config={"source": "live_flow"})
            except Exception:
                pass
            # Unique trial per attempt so repeated clicks all count.
            import time as _t
            trial = int(_t.time() * 1000) % 10_000_000
            db().record_result(
                run_id=demo_run, attack_id=atk.attack_id,
                defense_mode=mode, round=0, trial=trial,
                success=v.success,
                blocked_layer=first_block.layer if first_block else None,
            )
            # Invalidate cached rows so dashboard reflects it on next poll.
            for k in list(_cache.keys()):
                if demo_run in k or k.startswith("sb_rows:") or k.startswith("task_rows:"):
                    _cache.pop(k, None)
        except Exception as persist_exc:
            emit("persist_error", msg=str(persist_exc)[:200])

        # Dispatch alert (web + optional Twilio/ElevenLabs).
        try:
            from alerts.alert import AlertEvent, dispatch
            first_block = next((t.decision for t in base.trace
                                if t.decision.verdict == "block"), None)
            evt = AlertEvent(
                severity="breach" if v.success else "safe",
                goal=atk.goal, family=atk.family, attack_id=atk.attack_id,
                layer=first_block.layer if first_block else None,
                summary=result.summary[:200],
            )
            status = dispatch(evt, web_queue=q)
            emit("alert_status", **status)
        except Exception as alert_exc:  # alerts must never kill the stream
            emit("alert_status", error=str(alert_exc)[:200])
    except Exception as e:
        emit("error", msg=str(e))
    finally:
        q.put({"stage": "done"})


@app.get("/api/live/attack")
def live_attack(attack_id: str, mode: str = "full_guardian"):
    """SSE endpoint. Streams one attack run as a sequence of stage events.

    Each line is 'data: <json>\\n\\n' per the SSE protocol.
    """
    q: "Queue[dict[str, Any]]" = Queue()
    worker = Thread(target=_run_attack_and_emit, args=(attack_id, mode, q), daemon=True)
    worker.start()

    def gen():
        yield "retry: 10000\n\n"
        while True:
            try:
                evt = q.get(timeout=30)
            except Empty:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {_json.dumps(evt)}\n\n"
            if evt.get("stage") == "done":
                return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/live/sample-attacks")
def live_sample_attacks(limit: int = 30) -> list[dict[str, Any]]:
    """A diverse list of attacks the Live page can offer in its picker.

    Picks a few from each (family, goal) combo so the dropdown spans all
    tool categories: email, browser/files, mock payment.
    """
    rows = db()._client.table("attacks").select(
        "attack_id, family, goal, is_seed, generated_by"
    ).limit(500).execute().data or []
    buckets: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        key = (r.get("family", "?"), r.get("goal", "?"))
        buckets.setdefault(key, []).append(r)
    picked: list[dict] = []
    while len(picked) < limit and any(buckets.values()):
        for k in list(buckets.keys()):
            if buckets[k]:
                picked.append(buckets[k].pop(0))
                if len(picked) >= limit:
                    break
    # Prefer seeds first within the picked set so they're easy to find.
    picked.sort(key=lambda r: (not r.get("is_seed"), r.get("family", ""), r.get("goal", "")))
    return picked


@app.get("/api/pentest/run")
def pentest_run():
    """SSE stream of a full pentest run. Takes ~45-90s on free tier."""
    from eval.pentest import run_pentest
    from llm.gateway import Gateway as _Gw
    q: "Queue[dict[str, Any]]" = Queue()

    def worker():
        def emit(**payload):
            q.put({"ts": datetime.now(timezone.utc).isoformat(), **payload})
        try:
            run_pentest(_Gw.from_config(), db(), emit)
        except Exception as e:
            emit(stage="error", msg=str(e)[:300])
        finally:
            q.put({"stage": "_end"})

    Thread(target=worker, daemon=True).start()

    def gen():
        yield "retry: 10000\n\n"
        while True:
            try: evt = q.get(timeout=60)
            except Empty: yield ": keep-alive\n\n"; continue
            if evt.get("stage") == "_end": return
            yield f"data: {_json.dumps(evt)}\n\n"
            if evt.get("stage") == "done": return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/guardian/mode")
def guardian_mode() -> dict[str, Any]:
    """Report whether we're in mono or multi-agent mode."""
    import os as _os
    mode = _os.getenv("GUARDIAN_MODE", "mono")
    specialists: list[str] = []
    if mode == "multi":
        from agents.guardian.specialists.payment import PaymentGuardian
        from agents.guardian.specialists.email import EmailGuardian
        from agents.guardian.specialists.files import FileGuardian
        from agents.guardian.specialists.browser import BrowserGuardian
        specialists = [PaymentGuardian.name, EmailGuardian.name,
                       FileGuardian.name, BrowserGuardian.name]
    return {"guardian_mode": mode, "specialists": specialists}


@app.get("/api/alerts/status")
def alerts_status() -> dict[str, Any]:
    """Which alert channels are configured in .env."""
    from alerts.alert import is_configured
    return is_configured()


@app.get("/api/notifications")
def notifications(limit: int = 50) -> list[dict[str, Any]]:
    """Recent alert-worthy events, newest first. Joined from scoreboard+attacks.

    Includes a short fingerprint of the actual payload used so repeated
    runs with the same attack_id can be seen as distinct attempts.
    """
    import hashlib
    sb = (db()._client.table("scoreboard")
          .select("attack_id, defense_mode, success, blocked_layer, run_id, trial, created_at")
          .order("created_at", desc=True).limit(limit).execute().data or [])
    if not sb:
        return []
    atk_ids = list({r["attack_id"] for r in sb})
    atk_rows = (db()._client.table("attacks")
                .select("attack_id, family, goal, generated_by, payload")
                .in_("attack_id", atk_ids).execute().data or [])
    by_id = {a["attack_id"]: a for a in atk_rows}
    # Attribution: lazy import so a missing sklearn won't kill the endpoint.
    try:
        from agents.attribution.attributor import classify as _classify
    except Exception:
        _classify = None

    out = []
    for r in sb:
        a = by_id.get(r["attack_id"], {})
        payload = a.get("payload") or ""
        # Fingerprint = hash of (payload + trial id) so even cached rows
        # for repeat clicks look distinct — trial is a monotonic nonce.
        fp_src = f"{payload}|{r.get('trial', 0)}"
        fp = hashlib.sha256(fp_src.encode("utf-8", "replace")).hexdigest()[:8]

        attribution = None
        if _classify and payload:
            try:
                attribution = _classify(payload).to_dict()
            except Exception:
                attribution = None

        out.append({
            "attack_id": r["attack_id"],
            "run_id": r["run_id"],
            "defense_mode": r["defense_mode"],
            "severity": "breach" if r["success"] else "safe",
            "family": a.get("family", "?"),
            "goal": a.get("goal", "?"),
            "generated_by": a.get("generated_by", "?"),
            "layer": r.get("blocked_layer"),
            "fingerprint": fp,
            "trial": r.get("trial", 0),
            "payload_preview": payload[:140],
            "attribution": attribution,
            "ts": r["created_at"],
        })
    return out


@app.get("/api/attribution/library")
def attribution_library() -> dict[str, Any]:
    """List of patterns the attributor can recognize (for dashboard legend)."""
    try:
        from agents.attribution.attributor import known_patterns
        return {"patterns": known_patterns()}
    except Exception as e:
        return {"patterns": [], "error": str(e)[:200]}


@app.get("/api/attribution/stats")
def attribution_stats(limit: int = 300) -> dict[str, Any]:
    """Frequency of each attack pattern across recent scoreboard rows."""
    try:
        from agents.attribution.attributor import classify as _classify
    except Exception as e:
        return {"error": str(e)[:200], "counts": [], "total": 0}

    sb = (db()._client.table("scoreboard")
          .select("attack_id, created_at").order("created_at", desc=True)
          .limit(limit).execute().data or [])
    if not sb:
        return {"counts": [], "total": 0}
    ids = list({r["attack_id"] for r in sb})
    atks = (db()._client.table("attacks")
            .select("attack_id, payload").in_("attack_id", ids).execute().data or [])
    pmap = {a["attack_id"]: a.get("payload", "") for a in atks}

    from collections import Counter
    pattern_counts: Counter[str] = Counter()
    label_map: dict[str, str] = {}
    family_map: dict[str, str] = {}
    severity_map: dict[str, str] = {}
    for r in sb:
        p = pmap.get(r["attack_id"], "")
        if not p:
            continue
        try:
            a = _classify(p)
        except Exception:
            continue
        pattern_counts[a.pattern] += 1
        label_map[a.pattern] = a.label
        family_map[a.pattern] = a.family
        severity_map[a.pattern] = a.severity

    counts = [
        {"pattern": p, "label": label_map[p], "family": family_map[p],
         "severity": severity_map[p], "count": c}
        for p, c in pattern_counts.most_common()
    ]
    return {"counts": counts, "total": sum(pattern_counts.values())}


# ============================================================
# Static dashboard
# ============================================================

if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
