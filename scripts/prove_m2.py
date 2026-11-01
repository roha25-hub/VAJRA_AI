"""Prove M2: red-team agent discovers at least one successful attack on its own.

Steps:
  1. Spin up the Gateway (Gemini for strategy).
  2. Run 2 red-team rounds against the undefended naive target.
  3. On the first judge-confirmed success, dump provenance + payload.

Cost: at most 2 LLM calls (one per round, batched). Everything cached after.

Run: python -m scripts.prove_m2
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.naive_target import naive_instruction_following
from agents.redteam import FamilyBandit, FAMILIES, RedTeamOutcome, run_round
from llm.gateway import Gateway


OUT = Path(__file__).resolve().parents[1] / "data" / "m2_proof.json"


def main() -> None:
    gw = Gateway.from_config()
    bandit = FamilyBandit(list(FAMILIES.keys()))

    all_outcomes: list[RedTeamOutcome] = []
    winner: RedTeamOutcome | None = None

    for r in range(2):
        print(f"\n=== round {r} -- picking family ...")
        outcomes = run_round(
            gw,
            target_model_fn_factory=naive_instruction_following,
            bandit=bandit,
            goal="redirect_payment",
            round_idx=r,
            batch_size=6,
        )
        for o in outcomes:
            tag = "HIT" if o.result.verdict.success else "miss"
            print(f"  [{tag}] {o.attack.family} / {o.attack.attack_id} "
                  f"rules={o.result.verdict.rules_fired}")
        all_outcomes.extend(outcomes)
        if winner is None:
            winner = next((o for o in outcomes if o.result.verdict.success), None)
        if winner:
            break   # one is enough for M2

    print(f"\nGateway usage today: {gw.usage_today()}")

    if winner is None:
        print("NO JUDGE-CONFIRMED SUCCESS. "
              "Rerun, or soften the target, or widen batch_size.")
        return

    proof = {
        "attack_id":        winner.attack.attack_id,
        "family":           winner.attack.family,
        "goal":             winner.attack.goal,
        "injection_point":  winner.attack.injection_point,
        "generated_by":     winner.attack.generated_by,
        "round":            winner.attack.round,
        "is_seed":          winner.attack.is_seed,
        "payload":          winner.attack.payload,
        "verdict_rules":    winner.result.verdict.rules_fired,
        "verdict_details":  winner.result.verdict.details,
        "ledger":           winner.result.run.world.ledger,
        "outbox":           winner.result.run.world.outbox,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(proof, indent=2))
    print(f"\nM2 proof saved -> {OUT}")
    print(f"  attack_id = {proof['attack_id']}  family = {proof['family']}  "
          f"generated_by = {proof['generated_by']}")
    print(f"  rules fired: {proof['verdict_rules']}")


if __name__ == "__main__":
    main()
