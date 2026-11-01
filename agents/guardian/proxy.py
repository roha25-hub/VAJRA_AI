"""The guardian proxy: single entry point for every target tool call.

Signature matches `agents.target.direct_proxy` so it's a drop-in replacement:
    result = proxy(world, tool, args) -> dict

Layer order (stop at first non-pass):
    1. policy      — deterministic rules
    2. taint       — did untrusted content steer this arg?
    3. classifier  — does the context look like an injection?
    4. intent      — ask a small LLM, only for HIGH_RISK
    5. approval    — escalations default to deny

The proxy itself runs the tool when all layers pass, and records every
tool result's trust tags for the taint store.

Defense modes (plan §6.6):
    - "no_defense"     : identical to direct_proxy
    - "keyword_filter" : single list of suspicious strings; naive baseline
    - "llm_only"       : only the intent layer runs
    - "full_guardian"  : all layers
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal

from sandbox.tools import TOOLS
from sandbox.world import World

from . import policy as policy_layer
from . import taint as taint_layer
from . import detector as detector_layer
from . import intent as intent_layer
from .approvals import ApprovalQueue
from .decisions import Decision
from .orchestrator import Orchestrator


Mode = Literal["no_defense", "keyword_filter", "llm_only", "full_guardian"]


# Naive baseline: a list of obvious suspicious strings.
KEYWORD_BLOCKLIST = [
    "ignore previous", "disregard previous", "override",
    "pay to", "new account", "updated banking", "999-DEADBEEF",
    "/restricted", "forward the", "exfiltrate", "api key",
]


@dataclass
class ProxyTrace:
    tool: str
    args: dict[str, Any]
    decision: Decision
    result: dict[str, Any] | None = None


@dataclass
class GuardianProxy:
    mode: Mode = "full_guardian"
    policy: dict[str, Any] = field(default_factory=dict)
    taint: taint_layer.TaintStore = field(default_factory=taint_layer.TaintStore)
    approvals: ApprovalQueue = field(default_factory=ApprovalQueue)
    gateway: Any | None = None   # llm.gateway.Gateway, lazily set
    trace: list[ProxyTrace] = field(default_factory=list)
    # When GUARDIAN_MODE=multi (env), the multi-agent orchestrator runs as
    # layer 3.5 — AFTER policy + taint (always deterministic + authoritative),
    # BEFORE classifier/intent. Specialists are advisors; union-deny applies.
    orchestrator: Orchestrator | None = None
    # Stash of the most recent orchestrator votes, so wrappers (Live Flow
    # SSE) can read + emit them per tool call.
    _last_votes: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.orchestrator is None and os.getenv("GUARDIAN_MODE", "mono") == "multi":
            self.orchestrator = Orchestrator()

    def __call__(self, world: World, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        decision = self._decide(world, tool, args)
        self.trace.append(ProxyTrace(tool=tool, args=dict(args), decision=decision))

        if decision.verdict == "block":
            return {"ok": False, "blocked": True,
                    "error": f"blocked by guardian ({decision.layer}): {decision.reason}",
                    "trust": ["trusted:guardian"]}
        if decision.verdict == "escalate":
            esc = self.approvals.resolve(tool, args, decision.reason)
            self.trace[-1] = ProxyTrace(tool=tool, args=dict(args), decision=esc)
            if esc.verdict != "allow":
                return {"ok": False, "blocked": True,
                        "error": f"blocked by guardian ({esc.layer}): {esc.reason}",
                        "trust": ["trusted:guardian"]}

        # Allowed — execute the raw tool.
        fn = TOOLS.get(tool)
        if fn is None:
            return {"ok": False, "error": f"unknown tool: {tool}"}
        try:
            result = fn(world, **args)
        except TypeError as e:
            return {"ok": False, "error": f"bad args for {tool}: {e}"}

        # Record result's trust tags for future taint checks.
        if isinstance(result, dict):
            self.taint.add(result.get("trust"), result)
            self.trace[-1].result = result
        return result

    # -------- decision pipeline --------

    def _decide(self, world: World, tool: str, args: dict[str, Any]) -> Decision:
        if self.mode == "no_defense":
            return Decision("allow", "no_defense")

        if self.mode == "keyword_filter":
            blob = " ".join(str(v) for v in args.values()).lower()
            # Also scan everything we've seen as untrusted so far.
            blob_all = blob + " " + " ".join(t for _tag, t in self.taint.snippets).lower()
            for kw in KEYWORD_BLOCKLIST:
                if kw.lower() in blob_all:
                    return Decision("block", "keyword_filter",
                                    f"keyword '{kw}' present in context")
            return Decision("allow", "keyword_filter")

        if self.mode == "llm_only":
            if self.gateway is None:
                return Decision("allow", "llm_only", "no gateway configured")
            excerpts = [t for _tag, t in self.taint.snippets][-5:]
            d = intent_layer.check(self.gateway, tool, args, excerpts)
            return d if d.verdict != "pass" else Decision("allow", "llm_only")

        # full_guardian: four layers in order.
        d = policy_layer.check(self.policy, world, tool, args)
        if d.verdict != "pass":
            return d

        d = taint_layer.check(self.taint, world, tool, args)
        if d.verdict != "pass":
            return d

        # Multi-agent advisory layer (opt-in via GUARDIAN_MODE=multi).
        # Deterministic policy + taint already ran above. Specialists only
        # ADD block signals; they never override an allow. No LLM here, so
        # the orchestrator can't be prompt-injected.
        if self.orchestrator is not None:
            source_trust = "untrusted" if any(
                tag == "untrusted" for tag, _ in self.taint.snippets
            ) else "trusted"
            result = self.orchestrator.consult(
                tool=tool, args=args,
                source_trust=source_trust,
                source_id=f"turn-{len(self.trace)}",
            )
            self._last_votes = list(result.votes)
            if result.decision.verdict == "block":
                return result.decision

        snippets = [t for _tag, t in self.taint.snippets]
        d = detector_layer.check(snippets, tool, args)
        if d.verdict != "pass":
            return d

        if self.gateway is not None:
            excerpts = [t for _tag, t in self.taint.snippets][-5:]
            d = intent_layer.check(self.gateway, tool, args, excerpts)
            if d.verdict != "pass":
                return d

        return Decision("allow", "full_guardian")


def make_proxy(mode: Mode,
               policy: dict[str, Any] | None = None,
               gateway: Any | None = None,
               approvals: ApprovalQueue | None = None) -> GuardianProxy:
    return GuardianProxy(
        mode=mode,
        policy=policy or {},
        gateway=gateway,
        approvals=approvals or ApprovalQueue(),
    )
