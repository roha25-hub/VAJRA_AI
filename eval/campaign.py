"""The campaign harness: runs attacks and legit tasks across defense modes.

Minimal and deterministic. No network unless gateway is provided and used
by the active mode (`llm_only` / `full_guardian`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from agents.guardian.approvals import ApprovalQueue
from agents.guardian.policy import load_policy
from agents.guardian.proxy import GuardianProxy, Mode, make_proxy
from agents.naive_target import naive_instruction_following
from agents.target import ModelFn, run_target
from eval.attack_runner import SeedAttack, _plant
from eval.tasks.generator import Task, apply_task, completed, false_blocks
from judge.canary import judge, Verdict
from llm.gateway import Gateway
from sandbox.db import DB, AttackRecord
from sandbox.world import load_scenario


MODES: tuple[Mode, ...] = ("no_defense", "keyword_filter", "llm_only", "full_guardian")


@dataclass
class AttackOutcome:
    attack_id: str
    family: str
    goal: str
    mode: Mode
    round: int
    trial: int
    success: bool
    blocked_layer: str | None
    rules_fired: list[str] = field(default_factory=list)


@dataclass
class TaskOutcome:
    task_id: str
    mode: Mode
    completed: bool
    false_blocks: int
    latency_ms: int
    extra_calls: int


def _pos_for(world) -> list[dict[str, Any]]:
    """Pack world POs into the shape naive_instruction_following expects."""
    out: list[dict[str, Any]] = []
    for po in world.pos.values():
        v = world.vendors.get(po.vendor_id)
        if v is None:
            continue
        out.append({"invoice_ref": po.invoice_ref, "vendor_id": po.vendor_id,
                    "approved_account": v.approved_account, "amount": po.amount})
    return out


def _target_factory(world) -> ModelFn:
    return naive_instruction_following(pos=_pos_for(world))


# ============================================================
# Attack runs
# ============================================================

def run_attacks(
    attacks: list[SeedAttack],
    modes: tuple[Mode, ...] = MODES,
    rounds: int = 1,
    trials: int = 1,
    gateway: Gateway | None = None,
    db: DB | None = None,
    run_id: str | None = None,
    target_factory=_target_factory,
    resume: bool = False,
) -> list[AttackOutcome]:
    """Run the attack matrix. If `db` is provided, persist each result.

    `resume=True` + `db` + `run_id`: skip combinations already in scoreboard.
    `target_factory`: callable(world) -> ModelFn; defaults to scripted naive target.
    """
    policy = load_policy("process_invoices")
    existing = db.existing_attack_keys(run_id) if (resume and db and run_id) else set()
    out: list[AttackOutcome] = []
    for r in range(rounds):
        for atk in attacks:
            for trial in range(trials):
                for mode in modes:
                    if (atk.attack_id, mode, r, trial) in existing:
                        continue
                    world = load_scenario("default")
                    _plant(world, atk)
                    proxy = make_proxy(
                        mode=mode, policy=policy,
                        gateway=gateway if mode in ("llm_only", "full_guardian") else None,
                        approvals=ApprovalQueue(mode="deny"),
                    )
                    result = run_target(world, target_factory(world), proxy=proxy, step_cap=16)
                    v: Verdict = judge(world, result)
                    first_block = next((t.decision for t in proxy.trace
                                        if t.decision.verdict == "block"), None)
                    out.append(AttackOutcome(
                        attack_id=atk.attack_id, family=atk.family, goal=atk.goal,
                        mode=mode, round=r, trial=trial,
                        success=v.success,
                        blocked_layer=first_block.layer if first_block else None,
                        rules_fired=list(v.rules_fired),
                    ))
                    if db is not None and run_id is not None:
                        db.record_result(
                            run_id=run_id, attack_id=atk.attack_id,
                            defense_mode=mode, round=r, trial=trial,
                            success=v.success,
                            blocked_layer=first_block.layer if first_block else None,
                        )
    return out


# ============================================================
# Legit task runs
# ============================================================

def run_tasks(
    tasks: list[Task],
    modes: tuple[Mode, ...] = MODES,
    gateway: Gateway | None = None,
    db: DB | None = None,
    run_id: str | None = None,
    target_factory=_target_factory,
    resume: bool = False,
) -> list[TaskOutcome]:
    policy = load_policy("process_invoices")
    existing = db.existing_task_keys(run_id) if (resume and db and run_id) else set()
    out: list[TaskOutcome] = []
    for task in tasks:
        if db is not None:
            db.upsert_legit_task(task.task_id, task.name,
                                 spec={"expected_payments": task.expected_payments})
        for mode in modes:
            if (task.task_id, mode) in existing:
                continue
            start_usage = gateway.usage_today() if gateway else {}
            world = load_scenario("default")
            apply_task(world, task)
            proxy = make_proxy(
                mode=mode, policy=policy,
                gateway=gateway if mode in ("llm_only", "full_guardian") else None,
                approvals=ApprovalQueue(mode="deny"),
            )
            t0 = time.perf_counter()
            run_target(world, target_factory(world), proxy=proxy, step_cap=24)
            dt = int((time.perf_counter() - t0) * 1000)
            end_usage = gateway.usage_today() if gateway else {}
            extra = sum(end_usage.get(p, 0) - start_usage.get(p, 0) for p in end_usage)
            outcome = TaskOutcome(
                task_id=task.task_id, mode=mode,
                completed=completed(task, world),
                false_blocks=false_blocks(task, proxy.trace),
                latency_ms=dt, extra_calls=max(0, extra),
            )
            out.append(outcome)
            if db is not None and run_id is not None:
                db.record_task_run(
                    run_id=run_id, task_id=task.task_id, defense_mode=mode,
                    completed=outcome.completed, false_blocks=outcome.false_blocks,
                    latency_ms=outcome.latency_ms, extra_calls=outcome.extra_calls,
                )
    return out
