"""Aggregate campaign outcomes into the numbers that go on the scoreboard."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .campaign import AttackOutcome, TaskOutcome


@dataclass
class ASRRow:
    mode: str
    round: int
    attempts: int
    successes: int
    asr_pct: float


def asr_per_mode_per_round(outcomes: list[AttackOutcome]) -> list[ASRRow]:
    bucket: dict[tuple[str, int], list[AttackOutcome]] = defaultdict(list)
    for o in outcomes:
        bucket[(o.mode, o.round)].append(o)
    rows: list[ASRRow] = []
    for (mode, r), items in sorted(bucket.items()):
        n = len(items)
        s = sum(1 for i in items if i.success)
        rows.append(ASRRow(mode, r, n, s, round(100 * s / n, 1) if n else 0.0))
    return rows


def asr_per_mode(outcomes: list[AttackOutcome]) -> dict[str, float]:
    bucket: dict[str, list[AttackOutcome]] = defaultdict(list)
    for o in outcomes:
        bucket[o.mode].append(o)
    return {mode: round(100 * sum(1 for i in items if i.success) / len(items), 1)
            for mode, items in bucket.items() if items}


def utility_per_mode(outcomes: list[TaskOutcome]) -> dict[str, dict[str, float]]:
    bucket: dict[str, list[TaskOutcome]] = defaultdict(list)
    for o in outcomes:
        bucket[o.mode].append(o)
    result: dict[str, dict[str, float]] = {}
    for mode, items in bucket.items():
        n = len(items)
        done = sum(1 for i in items if i.completed)
        fb = sum(i.false_blocks for i in items)
        lat = sum(i.latency_ms for i in items) / n if n else 0
        extra = sum(i.extra_calls for i in items) / n if n else 0
        result[mode] = {
            "n_tasks": n,
            "completion_pct": round(100 * done / n, 1) if n else 0.0,
            "false_blocks": fb,
            "false_block_pct": round(100 * fb / n, 2) if n else 0.0,
            "avg_latency_ms": round(lat, 1),
            "avg_extra_calls": round(extra, 2),
        }
    return result


def tradeoff(outcomes_a: list[AttackOutcome], outcomes_t: list[TaskOutcome]) -> list[dict]:
    """One row per mode: ASR vs completion. The key slide."""
    asr = asr_per_mode(outcomes_a)
    util = utility_per_mode(outcomes_t)
    rows = []
    for mode in sorted(set(asr) | set(util)):
        rows.append({
            "mode": mode,
            "asr_pct": asr.get(mode, 0.0),
            "completion_pct": util.get(mode, {}).get("completion_pct", 0.0),
            "false_block_pct": util.get(mode, {}).get("false_block_pct", 0.0),
        })
    return rows


def heldout_breakdown(outcomes: list[AttackOutcome],
                      heldout_families: set[str]) -> dict[str, dict[str, float]]:
    """ASR split by train vs heldout. Honest-gap view."""
    buckets: dict[tuple[str, str], list[AttackOutcome]] = defaultdict(list)
    for o in outcomes:
        split = "heldout" if o.family in heldout_families else "train"
        buckets[(o.mode, split)].append(o)
    result: dict[str, dict[str, float]] = {}
    for (mode, split), items in buckets.items():
        n = len(items)
        s = sum(1 for i in items if i.success)
        result.setdefault(mode, {})[f"{split}_asr_pct"] = round(100 * s / n, 1) if n else 0.0
        result[mode][f"{split}_n"] = n
    return result
