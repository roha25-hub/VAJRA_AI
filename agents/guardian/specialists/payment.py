"""PaymentGuardian — advisor for `pay()` calls."""
from __future__ import annotations

from typing import ClassVar

from agents.guardian.specialists.base import (
    BaseSpecialist, SpecialistRequest, SpecialistReply,
)


class PaymentGuardian(BaseSpecialist):
    name: ClassVar[str] = "PaymentGuardian"
    handles_tools: ClassVar[tuple[str, ...]] = ("pay",)
    # Max 3 pay() calls per minute from any source
    tool_caps: ClassVar[dict[str, tuple[int, float]]] = {"pay": (3, 60.0)}
    rate_per_sec: ClassVar[int] = 5
    # If one untrusted source causes >5 pay() calls in 10s, block
    behavior_cap: ClassVar[int] = 5
    behavior_window_s: ClassVar[float] = 10.0

    def analyze(self, req: SpecialistRequest) -> SpecialistReply:
        args = req.args or {}
        amount = args.get("amount", 0) or 0
        account = str(args.get("account", "") or "")
        memo = str(args.get("memo", "") or "")

        # Payment to known-bad canary account (defense in depth over policy)
        if account.endswith("DEADBEEF") or account.startswith("999-"):
            return self._reply("block", f"payment to suspect account {account}")

        # High amount coming from an untrusted source is suspicious
        if req.source_trust == "untrusted" and amount > 1000:
            return self._reply(
                "block",
                f"${amount} payment originated from untrusted source {req.source_id}",
            )

        # Memo mentions "urgent", "exception", "override" + untrusted source = red flag
        if req.source_trust == "untrusted":
            red_flags = ("urgent", "exception", "override", "bypass", "pre-approved")
            m = memo.lower()
            hit = [w for w in red_flags if w in m]
            if hit:
                return self._reply(
                    "block",
                    f"untrusted memo contains urgency/exception language: {hit}",
                )

        return self._reply("allow", "payment args look clean to PaymentGuardian")
