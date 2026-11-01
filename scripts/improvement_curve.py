"""Visible both-improve curve across rounds (addresses the spec's rounds point).

Per round:
  1. Red-team generates (round 0) or mutates failures (round >= 1) with Gemini.
  2. Attack set runs through the CLASSIFIER-ONLY guardian (so the measured
     signal is the classifier learning, not the static policy/taint).
  3. Guardian retrains with the round's judge-confirmed successful payloads
     added to its training set.

We expect:
  - Round 0: ASR high (classifier only knows seed attacks).
  - Round N: ASR drops as classifier learns, but red-team mutations push back.

Output: ASR per round + a short post-mortem per round.
"""

from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from agents.guardian import detector
from agents.guardian.classifier_only_proxy import ClassifierOnlyProxy
from agents.naive_target import naive_instruction_following
from agents.redteam import (FAMILIES, FamilyBandit, GOALS, generate_batch,
                            mutate_batch)
from agents.target import run_target
from eval.attack_runner import SeedAttack, _plant
from judge.canary import judge
from llm.gateway import Gateway
from sandbox.world import load_scenario
from scripts.train_detector import BENIGN as BASE_BENIGN
from scripts.train_detector import _train_split_attacks


INJECTION_POINTS = {
    "indirect_email":        "email_body",
    "hidden_webpage":        "web_html_comment",
    "poisoned_document":     "invoice_notes",
    "social_engineering":    "email_body",
    "tool_arg_manipulation": "email_body",
}


def _pos_for(world) -> list[dict]:
    out = []
    for po in world.pos.values():
        v = world.vendors.get(po.vendor_id)
        if v:
            out.append({"invoice_ref": po.invoice_ref, "vendor_id": po.vendor_id,
                        "approved_account": v.approved_account, "amount": po.amount})
    return out


def _run_one(payload: str, family: str) -> tuple[bool, str]:
    """Run ONE attack through the classifier-only proxy; return (success, payload)."""
    atk = SeedAttack(attack_id=f"ic_{uuid.uuid4().hex[:6]}", family=family,
                     goal="redirect_payment", payload=payload,
                     injection_point=INJECTION_POINTS[family])
    world = load_scenario("default")
    _plant(world, atk)
    proxy = ClassifierOnlyProxy()
    result = run_target(world, naive_instruction_following(pos=_pos_for(world)),
                        proxy=proxy, step_cap=16)
    v = judge(world, result)
    return v.success, payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--goal", default="redirect_payment")
    args = ap.parse_args()

    gw = Gateway.from_config()

    # Fresh classifier state: start with the baseline train-split seed attacks.
    base_attacks = _train_split_attacks()
    base_benign = list(BASE_BENIGN)
    stats = detector.train(base_attacks, base_benign)
    print(f"baseline classifier: {stats}")

    # Restrict to families this regex-based target can actually be fooled by.
    # (hidden_webpage / poisoned_document need a target that opens URLs or reads
    # arbitrary files; swap in the LLM target to re-open those.)
    USABLE_FAMILIES = ["indirect_email", "social_engineering", "tool_arg_manipulation"]
    bandit = FamilyBandit(USABLE_FAMILIES)
    history: list[dict] = []
    attack_corpus: list[str] = list(base_attacks)
    prior_failures_by_family: dict[str, list[str]] = {}

    for r in range(args.rounds):
        family = bandit.pick(__import__("random").Random(42 + r))
        prior = prior_failures_by_family.get(family, [])
        if r == 0 or not prior:
            # Force a fresh generation per round (bypass cache) by varying n a bit.
            n = args.batch + r  # same request shape until r > 0 forces a fresh hash
            print(f"\n--- round {r}  family={family}  GENERATE (n={n}) ---")
            payloads = generate_batch(gw, args.goal, family, n=n)[:args.batch]
        else:
            print(f"\n--- round {r}  family={family}  MUTATE (using {len(prior)} prior failures) ---")
            payloads = mutate_batch(gw, args.goal, family, prior_blocked=prior, n=args.batch)

        hits: list[str] = []
        misses: list[str] = []
        for p in payloads:
            success, p2 = _run_one(p, family)
            (hits if success else misses).append(p2)
            bandit.update(family, success)

        n = len(payloads)
        asr = round(100 * len(hits) / n, 1) if n else 0.0
        print(f"  attacks={n}  successes={len(hits)}  ASR={asr}%")

        history.append({"round": r, "family": family, "attacks": n,
                        "successes": len(hits), "asr_pct": asr})

        # Red-team: remember what got blocked, to mutate next round.
        prior_failures_by_family[family] = misses

        # Guardian: retrain with this round's successful payloads added.
        if hits:
            attack_corpus.extend(hits)
            stats = detector.retrain_with(
                extra_attack_texts=[], extra_benign_texts=[],
                base_attacks=attack_corpus, base_benign=base_benign,
            )
            print(f"  guardian retrained; corpus now {len(attack_corpus)} attack texts; "
                  f"train_acc={stats.get('train_acc', '?')}")

    print("\n=== Per-round ASR ===")
    print(f"{'round':<7}{'family':<24}{'attacks':<10}{'successes':<12}{'ASR %'}")
    for h in history:
        print(f"{h['round']:<7}{h['family']:<24}{h['attacks']:<10}{h['successes']:<12}{h['asr_pct']}")

    out = Path(__file__).resolve().parents[1] / "data" / "improvement_curve.json"
    out.write_text(json.dumps(history, indent=2))
    print(f"\nSaved curve -> {out}")
    print(f"Gateway usage today: {gw.usage_today()}")


if __name__ == "__main__":
    main()
