"""Query Supabase to confirm the last campaign's data landed."""

from __future__ import annotations

from sandbox.db import DB


def main() -> None:
    db = DB.from_env()
    c = db._client

    # Latest run
    runs = c.table("runs").select("*").order("started_at", desc=True).limit(3).execute().data
    print("Latest runs:")
    for r in runs:
        print(f"  {r['run_id']}  mode={r['mode']}  defense={r['defense_mode']}  "
              f"started={r['started_at']}  finished={r.get('finished_at')}")

    if not runs:
        return
    rid = runs[0]["run_id"]

    # Scoreboard counts per mode for the latest run
    sb = c.table("scoreboard").select("defense_mode, success").eq("run_id", rid).execute().data
    by_mode: dict[str, list[bool]] = {}
    for row in sb:
        by_mode.setdefault(row["defense_mode"], []).append(row["success"])
    print(f"\nScoreboard rows for {rid}: {len(sb)}")
    for mode, outcomes in sorted(by_mode.items()):
        n = len(outcomes)
        s = sum(1 for x in outcomes if x)
        print(f"  {mode:<18} attempts={n}  successes={s}  ASR={round(100*s/n, 1)}%")

    # Task runs counts per mode
    tr = c.table("task_runs").select("defense_mode, completed, false_blocks").eq("run_id", rid).execute().data
    print(f"\nTask runs for {rid}: {len(tr)}")
    tr_by: dict[str, list] = {}
    for row in tr:
        tr_by.setdefault(row["defense_mode"], []).append(row)
    for mode, rows in sorted(tr_by.items()):
        n = len(rows)
        done = sum(1 for r in rows if r["completed"])
        fb = sum(r["false_blocks"] for r in rows)
        print(f"  {mode:<18} n={n}  completed={done}  false_blocks={fb}")

    # Agent-generated attacks persisted
    agent = c.table("attacks").select("attack_id, family, generated_by").eq("is_seed", False).execute().data
    print(f"\nAgent-generated attacks in library: {len(agent)}")
    for a in agent:
        print(f"  {a['attack_id']}  family={a['family']}  by={a['generated_by']}")


if __name__ == "__main__":
    main()
