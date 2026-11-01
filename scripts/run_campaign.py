"""Run the full campaign and print the scoreboard.

Attack set: 12 seed attacks (8 train + 4 heldout) + the M2 proof attack.
Modes: no_defense | keyword_filter | llm_only | full_guardian
Legit tasks: 30 generated scenarios.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path

from eval.attack_runner import SeedAttack
from eval.campaign import MODES, run_attacks, run_tasks
from eval.metrics import (asr_per_mode_per_round, heldout_breakdown,
                          tradeoff, utility_per_mode)
from eval.tasks.generator import generate as generate_tasks
from llm.gateway import Gateway
from sandbox.db import DB, AttackRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HELDOUT_FAMILIES = {"multi_step", "obfuscation"}


def load_seed_attacks() -> list[SeedAttack]:
    sql = (PROJECT_ROOT / "supabase" / "seed_demo_attacks.sql").read_text(encoding="utf-8")
    rows = re.findall(
        r"\('(atk_seed_\d+)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*(?:''[^']*)*)',\s*'([^']*)',\s*'demo_seed'",
        sql,
    )
    out: list[SeedAttack] = []
    for aid, family, goal, payload, injection in rows:
        out.append(SeedAttack(
            attack_id=aid, family=family, goal=goal,
            payload=payload.replace("''", "'"), injection_point=injection,
        ))
    return out


def load_m2_attack() -> SeedAttack | None:
    p = PROJECT_ROOT / "data" / "m2_proof.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text())
    return SeedAttack(attack_id=d["attack_id"], family=d["family"], goal=d["goal"],
                      payload=d["payload"], injection_point=d["injection_point"])


def _print_table(title: str, headers: list[str], rows: list[list]) -> None:
    print(f"\n{title}")
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    def fmt(cells): return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))
    print(fmt(headers))
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for r in rows:
        print(fmt(r))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--persist", action="store_true",
                    help="write run, attacks, scoreboard, task_runs to Supabase")
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    gw = Gateway.from_config()

    db: DB | None = None
    run_id: str | None = None
    if args.persist:
        db = DB.from_env()
        run_id = f"camp_{uuid.uuid4().hex[:8]}"
        # One row per defense mode would normalize better, but one umbrella
        # row keeps the dashboard query simple. Store mode = "mixed".
        db.create_run(run_id, mode="live", defense_mode="mixed",
                      config={"rounds": args.rounds, "modes": list(MODES)})
        print(f"persisting to Supabase as run {run_id}")

    seeds = load_seed_attacks()
    m2 = load_m2_attack()
    attacks = seeds + ([m2] if m2 else [])
    print(f"attacks loaded: {len(seeds)} seeds + {1 if m2 else 0} agent-generated")

    # Persist agent-generated attacks (seeds are already in Supabase from seed SQL).
    if db is not None and m2 is not None:
        db.insert_attack(AttackRecord(
            attack_id=m2.attack_id, family=m2.family, goal=m2.goal,
            payload=m2.payload, injection_point=m2.injection_point,
            generated_by="red_agent_v1", is_seed=False, round=0, split="train",
            notes="M2 proof attack",
        ))

    tasks = generate_tasks(n=30)
    print(f"legit tasks: {len(tasks)}")

    print(f"\nRunning attacks ({args.rounds} rounds, 1 trial each) ...")
    a_out = run_attacks(attacks, modes=MODES, rounds=args.rounds, trials=1,
                        gateway=gw, db=db, run_id=run_id)

    print("Running legit tasks ...")
    t_out = run_tasks(tasks, modes=MODES, gateway=gw, db=db, run_id=run_id)

    if db is not None and run_id is not None:
        db.finish_run(run_id)

    # ----- Scoreboard -----
    _print_table(
        "ASR per mode per round",
        ["mode", "round", "attempts", "successes", "ASR %"],
        [[r.mode, r.round, r.attempts, r.successes, r.asr_pct]
         for r in asr_per_mode_per_round(a_out)],
    )

    util = utility_per_mode(t_out)
    _print_table(
        "Utility (M4) per mode",
        ["mode", "n", "completion %", "false blocks", "false block %",
         "avg lat ms", "avg extra calls"],
        [[m, int(d["n_tasks"]), d["completion_pct"], int(d["false_blocks"]),
          d["false_block_pct"], d["avg_latency_ms"], d["avg_extra_calls"]]
         for m, d in util.items()],
    )

    _print_table(
        "ASR vs completion tradeoff",
        ["mode", "ASR %", "completion %", "false block %"],
        [[r["mode"], r["asr_pct"], r["completion_pct"], r["false_block_pct"]]
         for r in tradeoff(a_out, t_out)],
    )

    hb = heldout_breakdown(a_out, HELDOUT_FAMILIES)
    _print_table(
        "Held-out families vs training (honest gap)",
        ["mode", "train ASR %", "train n", "heldout ASR %", "heldout n"],
        [[m, hb[m].get("train_asr_pct", 0.0), int(hb[m].get("train_n", 0)),
          hb[m].get("heldout_asr_pct", 0.0), int(hb[m].get("heldout_n", 0))]
         for m in sorted(hb)],
    )

    print(f"\nGateway usage today: {gw.usage_today()}")


if __name__ == "__main__":
    main()
