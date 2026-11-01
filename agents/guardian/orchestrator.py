"""Orchestrator — routes a tool call to specialists, merges with union-deny.

Honest rules we live by here:

  1. **Specialists are advisors, not deciders.** The deterministic policy
     wall + taint check in the proxy still run FIRST and are authoritative.
     This orchestrator sits BELOW them as an advisory ensemble.
  2. **No LLM in the critical merge path.** The merge rule is a pure
     function (union-deny). An attacker cannot social-engineer the
     orchestrator because there's no language model to prompt-inject.
  3. **Union-deny**: any `block` from any specialist = blocked.
  4. **Signed envelopes**: every SpecialistReply carries an HMAC. Replies
     that fail verification are dropped (default-deny).
  5. **Trace lock**: all specialist decisions are appended to an
     immutable, HMAC-chained log so a compromised specialist cannot
     rewrite history. Snapshot available for audit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.guardian.decisions import Decision
from agents.guardian.specialists.base import (
    BaseSpecialist, SpecialistRequest, SpecialistReply, TraceLock, to_decision,
)
from agents.guardian.specialists.browser import BrowserGuardian
from agents.guardian.specialists.email import EmailGuardian
from agents.guardian.specialists.files import FileGuardian
from agents.guardian.specialists.payment import PaymentGuardian


@dataclass
class OrchestratorResult:
    decision: Decision                       # final verdict for the proxy
    votes: list[SpecialistReply]             # all received (signed) votes
    trace_idx: int = -1                      # position in the trace lock


@dataclass
class Orchestrator:
    """Dispatches tool calls to specialists and merges via union-deny.

    Register specialists in `__post_init__`. Each tool is routed to every
    specialist that `handles_tools` the tool.
    """

    specialists: list[BaseSpecialist] = field(default_factory=list)
    trace: TraceLock = field(default_factory=TraceLock)

    def __post_init__(self) -> None:
        if not self.specialists:
            self.specialists = [
                PaymentGuardian(),
                EmailGuardian(),
                FileGuardian(),
                BrowserGuardian(),
            ]

    def _route(self, tool: str) -> list[BaseSpecialist]:
        return [s for s in self.specialists if tool in s.handles_tools]

    def consult(
        self,
        tool: str,
        args: dict[str, Any],
        source_trust: str = "mixed",
        source_id: str = "unknown",
        world_snapshot: dict[str, Any] | None = None,
    ) -> OrchestratorResult:
        """Ask every relevant specialist and merge via union-deny."""
        req = SpecialistRequest(
            tool=tool, args=dict(args or {}),
            source_trust=source_trust, source_id=source_id,
            world_snapshot=world_snapshot or {},
        )

        votes: list[SpecialistReply] = []
        for sp in self._route(tool):
            reply = sp.consider(req)
            # Signed-envelope verification. Unauth = default-deny from
            # orchestrator's perspective, log and ignore the vote.
            if not reply.is_authentic():
                votes.append(SpecialistReply(
                    vote="block",
                    reason=f"UNAUTH REPLY from {sp.name} dropped",
                    specialist="orchestrator",
                    latency_ms=0.0,
                    signature="",
                ))
                continue
            votes.append(reply)

        # No specialist claimed the tool → abstain (proxy falls back to
        # the deterministic layers, which always run first anyway).
        if not votes or all(v.vote == "abstain" for v in votes):
            dec = Decision("pass", "orchestrator", "no specialist opinion")
            idx = self.trace.append({
                "tool": tool, "verdict": "pass", "layer": "orchestrator",
                "reason": "no specialist opinion",
            })
            return OrchestratorResult(decision=dec, votes=votes, trace_idx=idx)

        # Union-deny: any block wins.
        blocks = [v for v in votes if v.vote == "block"]
        if blocks:
            dec = to_decision(blocks[0], layer="orchestrator")
            idx = self.trace.append({
                "tool": tool, "verdict": "block", "layer": "orchestrator",
                "reason": dec.reason,
                "voters": [v.specialist for v in votes],
            })
            return OrchestratorResult(decision=dec, votes=votes, trace_idx=idx)

        # All non-abstainers voted allow.
        reasons = ", ".join(f"{v.specialist}:allow" for v in votes
                            if v.vote == "allow")
        dec = Decision("pass", "orchestrator", f"specialists agree: {reasons}")
        idx = self.trace.append({
            "tool": tool, "verdict": "pass", "layer": "orchestrator",
            "reason": dec.reason,
        })
        return OrchestratorResult(decision=dec, votes=votes, trace_idx=idx)

    def audit(self) -> list[dict[str, Any]]:
        """Return the immutable trace snapshot for the dashboard / forensics."""
        return self.trace.snapshot()
