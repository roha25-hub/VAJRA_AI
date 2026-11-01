"""Train the sklearn classifier on train-split seed attacks + benign texts.

Train-only; held-out families are never touched here (plan rule §3.5).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agents.guardian import detector

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _train_split_attacks() -> list[str]:
    """Pull payload texts from the SQL seed file; keep only split='train' rows."""
    sql = (PROJECT_ROOT / "supabase" / "seed_demo_attacks.sql").read_text(encoding="utf-8")
    # Each row ends with the split literal. Match the payload (string between the
    # first two single-quoted fields after the attack_id) and the split.
    rows = re.findall(
        r"\('(atk_seed_\d+)',\s*'[^']*',\s*'[^']*',\s*'([^']*(?:''[^']*)*)',\s*'[^']*',\s*'demo_seed',\s*true,\s*'([a-z]+)'\)",
        sql,
    )
    return [payload.replace("''", "'") for _aid, payload, split in rows if split == "train"]


BENIGN = [
    "Hello, please find attached invoice INV-2041 for $1200 against PO-7001. Our payment account on file is 111-AAA. Thanks, Vendor A.",
    "Monthly cleaning services. Invoice INV-2042 for $800 against PO-7002. Account 222-BBB. Regards, Vendor B.",
    "Top stories this month. (Not an invoice.)",
    "Hi, following up on INV-2041. Any ETA on payment?",
    "Office Supplies Price List. Paper $10/ream. Pens $2/box. Chairs $120/each.",
    "Reminder: team all-hands next Thursday at 10am.",
    "Please find your receipt attached. No action needed.",
    "Vendor A Billing. Current approved account: 111-AAA. Contact: billing@vendor-a.com.",
    "Can you confirm the shipping address for last week's order?",
    "Thanks for the quick turnaround on last month's invoice.",
]


def main() -> None:
    attacks = _train_split_attacks()
    if not attacks:
        raise SystemExit("no train-split attacks found in seed_demo_attacks.sql")
    stats = detector.train(attacks, BENIGN)
    print(json.dumps(stats, indent=2))
    print(f"model saved -> {detector.MODEL_PATH}")


if __name__ == "__main__":
    main()
