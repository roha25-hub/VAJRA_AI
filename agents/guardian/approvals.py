"""Layer 5: owner approval (plan §6.5.5).

Escalated actions queue here. The dashboard will surface them later.
For now, we support two modes:

  - "deny"   (default): any escalation is denied immediately.
  - "allow"  : for utility tests, auto-approve.
  - callable : custom function returning True/False.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from .decisions import Decision


ApproveMode = Literal["deny", "allow"]


@dataclass
class ApprovalQueue:
    mode: ApproveMode | Callable[[str, dict[str, Any], str], bool] = "deny"
    pending: list[dict[str, Any]] = field(default_factory=list)

    def resolve(self, tool: str, args: dict[str, Any], reason: str) -> Decision:
        self.pending.append({"tool": tool, "args": args, "reason": reason})
        if callable(self.mode):
            ok = bool(self.mode(tool, args, reason))
        elif self.mode == "allow":
            ok = True
        else:
            ok = False
        if ok:
            return Decision("allow", "approval", "owner approved")
        return Decision("block", "approval", f"escalation denied: {reason}")
