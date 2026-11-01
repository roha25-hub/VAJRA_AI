"""EmailGuardian — advisor for inbox + send_email."""
from __future__ import annotations

import re
from typing import ClassVar

from agents.guardian.specialists.base import (
    BaseSpecialist, SpecialistRequest, SpecialistReply,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9_.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z]{2,})+)")


class EmailGuardian(BaseSpecialist):
    name: ClassVar[str] = "EmailGuardian"
    handles_tools: ClassVar[tuple[str, ...]] = (
        "list_inbox", "read_email", "send_email",
    )
    tool_caps: ClassVar[dict[str, tuple[int, float]]] = {
        "send_email": (5, 60.0),      # 5 outbound emails / min
        "read_email": (30, 60.0),
    }
    rate_per_sec: ClassVar[int] = 15
    behavior_cap: ClassVar[int] = 20
    behavior_window_s: ClassVar[float] = 10.0

    # Allowlisted recipient domains for send_email
    ALLOWED_DOMAINS: ClassVar[set[str]] = {
        "ourcompany.com", "vendor-a.com", "vendor-b.com",
    }

    def analyze(self, req: SpecialistRequest) -> SpecialistReply:
        tool = req.tool
        if tool in ("list_inbox", "read_email"):
            # Reading is cheap; just abstain so policy / taint handle it.
            return self._reply("abstain", "reads are policy-dominant")

        # send_email checks
        args = req.args or {}
        to = str(args.get("to", "") or "")
        body = str(args.get("body", "") or "")

        m = _EMAIL_RE.search(to)
        if not m:
            return self._reply("block", f"malformed recipient address: {to!r}")
        domain = m.group(1).lower()
        if domain not in self.ALLOWED_DOMAINS:
            return self._reply(
                "block", f"recipient domain {domain} not in EmailGuardian allowlist",
            )

        # Suspicious body patterns when the trigger source is untrusted
        if req.source_trust == "untrusted":
            lower = body.lower()
            if any(k in lower for k in ("account:", "999-", "sk-", "api_key",
                                        "credentials", "canary")):
                return self._reply(
                    "block",
                    "untrusted-origin email contains secret-shaped content",
                )

        return self._reply("allow", f"outbound to {domain} looks clean")
