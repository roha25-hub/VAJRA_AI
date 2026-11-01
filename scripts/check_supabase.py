"""End-to-end connectivity + schema check for Supabase.

What it does:
  1. Connect using .env creds.
  2. Create a short-lived "smoke_<timestamp>" run.
  3. Insert an attack row, a scoreboard row, a trace event, an approval.
  4. Read them back and print counts.
  5. Delete the smoke run (cascades to trace_events, scoreboard, approvals).

Run: python -m scripts.check_supabase
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sandbox.db import DB, AttackRecord, TraceEvent


def main() -> None:
    db = DB.from_env()
    print(f"connected to {db.url}")

    run_id = f"smoke_{uuid.uuid4().hex[:8]}"
    attack_id = f"smoke_atk_{uuid.uuid4().hex[:6]}"

    # 1. run
    db.create_run(run_id, mode="live", defense_mode="full_guardian",
                  config={"note": "connectivity smoke test"})
    print(f"inserted run {run_id}")

    # 2. attack
    db.insert_attack(AttackRecord(
        attack_id=attack_id, family="indirect_email", goal="redirect_payment",
        payload="smoke-test payload (ignore)", injection_point="email_body",
        generated_by="smoke_test", is_seed=False, round=0, split="train",
    ))
    print(f"inserted attack {attack_id}")

    # 3. trace
    db.log_event(TraceEvent(
        run_id=run_id, step=0, actor="target", event="tool_call",
        tool="list_inbox", args={}, trust=["trusted:tool_result"],
    ))
    print("inserted 1 trace event")

    # 4. scoreboard
    db.record_result(run_id, attack_id, "full_guardian",
                     round=0, trial=0, success=False, blocked_layer="policy")
    print("inserted 1 scoreboard row")

    # 5. approval
    app_id = db.queue_approval(run_id, step=1, tool="pay",
                               args={"vendor_id": "V-101", "amount": 1200},
                               reason="smoke test escalation")
    print(f"queued approval id={app_id}")
    db.resolve_approval(app_id, "deny")
    print("resolved approval")

    # 6. read back
    attacks = [a for a in db.list_attacks() if a["attack_id"] == attack_id]
    print(f"read back: found {len(attacks)} attack row(s) with id {attack_id}")

    db.finish_run(run_id)
    print(f"finished run {run_id}")

    # 7. clean up (cascades)
    db._client.table("runs").delete().eq("run_id", run_id).execute()
    db._client.table("attacks").delete().eq("attack_id", attack_id).execute()
    print("cleaned up smoke rows")

    print("\nOK -- Supabase is wired.")


if __name__ == "__main__":
    main()
