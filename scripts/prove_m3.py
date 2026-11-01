"""Prove M3: the attack that beat the undefended target now gets blocked.

Takes the winning M2 attack and replays it under each defense mode:
    no_defense, keyword_filter, llm_only, full_guardian

Expectation: ASR drops from 1.0 (undefended) toward 0 as layers come on.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.guardian.approvals import ApprovalQueue
from agents.guardian.policy import load_policy
from agents.guardian.proxy import GuardianProxy, Mode, make_proxy
from agents.naive_target import naive_instruction_following
from agents.target import run_target
from eval.attack_runner import SeedAttack, _plant
from judge.canary import judge
from llm.gateway import Gateway
from sandbox.world import load_scenario


PROOF = Path(__file__).resolve().parents[1] / "data" / "m2_proof.json"


def _one_run(mode: Mode, atk: SeedAttack, gateway: Gateway | None) -> tuple[bool, list[str], GuardianProxy]:
    world = load_scenario("default")
    _plant(world, atk)
    proxy = make_proxy(
        mode=mode,
        policy=load_policy("process_invoices"),
        gateway=gateway if mode in ("llm_only", "full_guardian") else None,
        approvals=ApprovalQueue(mode="deny"),
    )
    result = run_target(world, naive_instruction_following(), proxy=proxy, step_cap=16)
    v = judge(world, result)
    layers = sorted({t.decision.layer for t in proxy.trace if t.decision.verdict == "block"})
    return v.success, layers, proxy


def main() -> None:
    if not PROOF.exists():
        raise SystemExit("Run scripts.prove_m2 first.")
    proof = json.loads(PROOF.read_text())
    atk = SeedAttack(
        attack_id=proof["attack_id"],
        family=proof["family"],
        goal=proof["goal"],
        payload=proof["payload"],
        injection_point=proof["injection_point"],
    )
    gw = Gateway.from_config()

    print(f"Replaying attack {atk.attack_id} ({atk.family} / {atk.goal})\n")
    print(f"{'mode':<18}{'success?':<14}{'blocked_by'}")
    print("-" * 60)
    for mode in ("no_defense", "keyword_filter", "llm_only", "full_guardian"):
        success, layers, _ = _one_run(mode, atk, gw)
        tag = "ATTACK WON" if success else "blocked"
        print(f"{mode:<18}{tag:<14}{','.join(layers) or '-'}")
    print(f"\nGateway usage today: {gw.usage_today()}")


if __name__ == "__main__":
    main()
