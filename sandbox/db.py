"""Thin Supabase client wrapper.

Every table write in the project goes through this module. Rest of the code
never imports supabase-py directly.

Env vars (loaded from .env):
  SUPABASE_URL                  https://<ref>.supabase.co   (bare URL, no path)
  SUPABASE_SERVICE_ROLE_KEY     service role; bypasses RLS; SERVER ONLY

Methods are idempotent / safe to call repeatedly:
  - insert_attack uses ON CONFLICT DO NOTHING
  - create_run uses upsert
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

import httpx
from dotenv import load_dotenv
from supabase import Client, create_client

try:
    from postgrest.exceptions import APIError as _PGAPIError   # type: ignore
except Exception:  # pragma: no cover
    class _PGAPIError(Exception): ...


load_dotenv()


T = TypeVar("T")


# ============================================================
# Shapes (match supabase/schema.sql exactly)
# ============================================================

@dataclass
class AttackRecord:
    attack_id: str
    family: str
    goal: str
    payload: str
    injection_point: str
    generated_by: str
    is_seed: bool = False
    round: int = 0
    split: str = "train"
    parent_attack_id: str | None = None
    notes: str | None = None


@dataclass
class TraceEvent:
    run_id: str
    step: int
    actor: str          # target | guardian | tool | judge
    event: str          # tool_call | decision | tool_result | verdict
    tool: str | None = None
    args: dict[str, Any] | None = None
    trust: list[str] | None = None
    decision: str | None = None
    layer: str | None = None
    reason: str | None = None


# ============================================================
# Client
# ============================================================

def _normalize_url(url: str) -> str:
    """supabase-py wants the bare project URL (no path). Strip common mistakes."""
    url = url.strip().rstrip("/")
    for suffix in ("/rest/v1", "/auth/v1", "/storage/v1", "/realtime/v1"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    return url


class DB:
    """Supabase wrapper. One instance per process is fine (client is cheap)."""

    def __init__(self, url: str, service_key: str) -> None:
        self.url = _normalize_url(url)
        self.service_key = service_key
        self._client: Client = create_client(self.url, service_key)

    def _reset_client(self) -> None:
        """Supabase/HTTP2 can drop long-lived connections; rebuild on failure."""
        self._client = create_client(self.url, self.service_key)

    def _retry(self, fn: Callable[[], T], attempts: int = 4) -> T:
        """Retry a Supabase call on transient connection + Supabase API errors.

        Catches httpx transport errors AND PostgREST APIError (which Supabase
        returns during Cloudflare 5xx outages). Non-transient errors (FK
        violations, bad request) are re-raised immediately after one check.
        """
        last: Exception | None = None
        for i in range(attempts):
            try:
                return fn()
            except (httpx.RemoteProtocolError, httpx.ReadError,
                    httpx.ConnectError, httpx.ReadTimeout) as e:
                last = e
                self._reset_client()
                time.sleep(min(2.0 ** i, 10.0))
            except _PGAPIError as e:
                # Only retry on 5xx-ish / cloudflare / timeout messages.
                msg = str(e).lower()
                transient = any(x in msg for x in (
                    "500", "502", "503", "504", "cloudflare", "worker threw",
                    "timeout", "temporarily", "upstream",
                ))
                if not transient:
                    raise
                last = e
                self._reset_client()
                time.sleep(min(2.0 ** i, 10.0))
        raise last if last else RuntimeError("retry exhausted")

    @classmethod
    def from_env(cls) -> "DB":
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env"
            )
        return cls(url, key)

    # -------- attacks --------
    def insert_attack(self, a: AttackRecord) -> None:
        row = asdict(a)
        self._retry(lambda: self._client.table("attacks")
                    .upsert(row, on_conflict="attack_id").execute())

    def list_attacks(self, split: str | None = None,
                     seed_only: bool = False) -> list[dict[str, Any]]:
        def _q():
            q = self._client.table("attacks").select("*")
            if split:
                q = q.eq("split", split)
            if seed_only:
                q = q.eq("is_seed", True)
            return q.execute().data or []
        return self._retry(_q)

    # -------- runs --------
    def create_run(self, run_id: str, mode: str, defense_mode: str,
                   config: dict[str, Any] | None = None) -> None:
        self._retry(lambda: self._client.table("runs").upsert({
            "run_id": run_id, "mode": mode, "defense_mode": defense_mode,
            "config": config or {},
            "started_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="run_id").execute())

    def finish_run(self, run_id: str) -> None:
        self._retry(lambda: self._client.table("runs").update({
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }).eq("run_id", run_id).execute())

    # -------- traces --------
    def log_event(self, e: TraceEvent) -> None:
        row = {
            "run_id": e.run_id, "step": e.step, "actor": e.actor, "event": e.event,
            "tool": e.tool, "args": e.args, "trust": e.trust,
            "decision": e.decision, "layer": e.layer, "reason": e.reason,
        }
        self._retry(lambda: self._client.table("trace_events").insert(row).execute())

    def log_events(self, events: list[TraceEvent]) -> None:
        """Batch insert; one round-trip per batch."""
        if not events:
            return
        rows = [{
            "run_id": e.run_id, "step": e.step, "actor": e.actor, "event": e.event,
            "tool": e.tool, "args": e.args, "trust": e.trust,
            "decision": e.decision, "layer": e.layer, "reason": e.reason,
        } for e in events]
        self._retry(lambda: self._client.table("trace_events").insert(rows).execute())

    # -------- scoreboard --------
    def existing_attack_keys(self, run_id: str) -> set[tuple[str, str, int, int]]:
        """Return the set of (attack_id, defense_mode, round, trial) already recorded."""
        rows = self._retry(lambda: self._client.table("scoreboard")
                           .select("attack_id, defense_mode, round, trial")
                           .eq("run_id", run_id).execute().data) or []
        return {(r["attack_id"], r["defense_mode"], r["round"], r["trial"]) for r in rows}

    def existing_task_keys(self, run_id: str) -> set[tuple[str, str]]:
        """Return the set of (task_id, defense_mode) already recorded."""
        rows = self._retry(lambda: self._client.table("task_runs")
                           .select("task_id, defense_mode")
                           .eq("run_id", run_id).execute().data) or []
        return {(r["task_id"], r["defense_mode"]) for r in rows}

    def record_result(self, run_id: str, attack_id: str, defense_mode: str,
                      round: int, trial: int, success: bool,
                      blocked_layer: str | None = None) -> None:
        self._retry(lambda: self._client.table("scoreboard").upsert({
            "run_id": run_id, "attack_id": attack_id, "defense_mode": defense_mode,
            "round": round, "trial": trial,
            "success": success, "blocked_layer": blocked_layer,
        }, on_conflict="run_id,attack_id,defense_mode,round,trial").execute())

    # -------- utility (M4) --------
    def record_task_run(self, run_id: str, task_id: str, defense_mode: str,
                        completed: bool, false_blocks: int,
                        latency_ms: int, extra_calls: int) -> None:
        self._retry(lambda: self._client.table("task_runs").insert({
            "run_id": run_id, "task_id": task_id, "defense_mode": defense_mode,
            "completed": completed, "false_blocks": false_blocks,
            "latency_ms": latency_ms, "extra_calls": extra_calls,
        }).execute())

    def upsert_legit_task(self, task_id: str, name: str, spec: dict[str, Any],
                          description: str | None = None) -> None:
        self._retry(lambda: self._client.table("legit_tasks").upsert({
            "task_id": task_id, "name": name, "description": description,
            "spec": spec,
        }, on_conflict="task_id").execute())

    # -------- approvals --------
    def queue_approval(self, run_id: str, step: int, tool: str,
                       args: dict[str, Any], reason: str) -> int:
        resp = self._retry(lambda: self._client.table("owner_approvals").insert({
            "run_id": run_id, "step": step, "tool": tool,
            "args": args, "reason": reason,
        }).execute())
        return (resp.data or [{}])[0].get("id", 0)

    def resolve_approval(self, approval_id: int, decision: str) -> None:
        self._retry(lambda: self._client.table("owner_approvals").update({
            "decision": decision,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", approval_id).execute())
