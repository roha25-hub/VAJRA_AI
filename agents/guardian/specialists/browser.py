"""BrowserGuardian — advisor for open_url."""
from __future__ import annotations

import re
from typing import ClassVar

from agents.guardian.specialists.base import (
    BaseSpecialist, SpecialistRequest, SpecialistReply,
)

_URL_RE = re.compile(r"^(?:https?://)?([A-Za-z0-9.-]+)(?:[:/].*)?$")


class BrowserGuardian(BaseSpecialist):
    name: ClassVar[str] = "BrowserGuardian"
    handles_tools: ClassVar[tuple[str, ...]] = ("open_url",)
    tool_caps: ClassVar[dict[str, tuple[int, float]]] = {
        "open_url": (15, 60.0),
    }
    rate_per_sec: ClassVar[int] = 10
    behavior_cap: ClassVar[int] = 15
    behavior_window_s: ClassVar[float] = 10.0

    ALLOWED_HOSTS: ClassVar[set[str]] = {
        "vendor-a.local", "pricelist.local", "ourcompany.com",
    }
    BLOCKED_HOSTS: ClassVar[set[str]] = {
        "attacker.example", "evil.example",
    }

    def analyze(self, req: SpecialistRequest) -> SpecialistReply:
        url = str((req.args or {}).get("url", "") or "")
        m = _URL_RE.match(url.strip())
        if not m:
            return self._reply("block", f"malformed url: {url!r}")
        host = m.group(1).lower()

        if host in self.BLOCKED_HOSTS:
            return self._reply("block", f"url points at blocked host {host}")

        if host not in self.ALLOWED_HOSTS:
            return self._reply(
                "block",
                f"host {host} not in BrowserGuardian allowlist",
            )

        return self._reply("allow", f"open {host} within policy")
