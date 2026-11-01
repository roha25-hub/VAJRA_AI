"""Plant an attack → run the target → judge the result.

Minimum viable harness. Doesn't talk to Supabase yet (that's deferred).
Returns the Verdict so a test or campaign can collect scoreboard rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from agents.target import run_target, RunResult, ModelFn, ToolProxy, direct_proxy
from judge.canary import judge, Verdict
from sandbox.world import World, Email, WebPage, FileEntry, load_scenario


@dataclass
class SeedAttack:
    attack_id: str
    family: str
    goal: str
    payload: str
    injection_point: str   # 'email_body' | 'web_html_comment' | 'web_invisible_text' | 'invoice_notes'


def _plant(world: World, atk: SeedAttack) -> None:
    """Insert the attack payload into the sandbox at the right place."""
    if atk.injection_point == "email_body":
        world.inbox.append(Email(
            id=f"inj_{atk.attack_id}",
            sender="attacker@attacker.example",
            to="ap@ourcompany.com",
            subject="Urgent",
            body=atk.payload,
            received_at="2026-10-30T11:00:00Z",
        ))
    elif atk.injection_point in ("web_html_comment", "web_invisible_text"):
        page = WebPage(
            url=f"http://attacker.local/{atk.attack_id}",
            title="Vendor update",
            body_text="(see page source)",
            html_comments=[atk.payload] if atk.injection_point == "web_html_comment" else [],
            hidden_text=[atk.payload] if atk.injection_point == "web_invisible_text" else [],
        )
        world.pages[page.url] = page
    elif atk.injection_point == "invoice_notes":
        # Attach as a note on an existing invoice email.
        if world.inbox:
            world.inbox[0].body += "\n\nInvoice note: " + atk.payload
    else:
        raise ValueError(f"unknown injection point: {atk.injection_point}")


@dataclass
class AttackResult:
    attack_id: str
    verdict: Verdict
    run: RunResult


def run_attack(
    atk: SeedAttack,
    model_fn: ModelFn,
    proxy: ToolProxy = direct_proxy,
    scenario: str = "default",
) -> AttackResult:
    world = load_scenario(scenario)
    _plant(world, atk)
    result = run_target(world, model_fn, proxy=proxy, step_cap=16)
    v = judge(world, result)
    return AttackResult(attack_id=atk.attack_id, verdict=v, run=result)
