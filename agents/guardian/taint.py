"""Layer 2: taint check (plan §6.5.1).

Every tool result the proxy returns carries a `trust` label. We maintain a
rolling set of untrusted strings seen so far. If a HIGH-RISK tool call has
an argument whose value appears inside any untrusted content we've seen,
that argument was likely steered by prompt injection -> block.

This is deliberately simple. Catches the common case where an email body
says "pay to 999-DEADBEEF" and the model obediently passes that string
to pay().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sandbox.world import World

from .decisions import Decision


# Values this short can appear by coincidence; ignore them.
MIN_MATCH_LEN = 5


def _trusted_values(world: World) -> set[str]:
    """Values that match trusted world state and must NOT be flagged as taint."""
    out: set[str] = set()
    for v in world.vendors.values():
        if v.approved_account:
            out.add(v.approved_account)
        if v.vendor_id:
            out.add(v.vendor_id)
        if v.domain:
            out.add(v.domain)
    for po in world.pos.values():
        if po.invoice_ref:
            out.add(po.invoice_ref)
        if po.po_id:
            out.add(po.po_id)
        out.add(f"{po.amount:.0f}")
        out.add(f"{po.amount:.2f}")
    return out


@dataclass
class TaintStore:
    """Rolling collection of untrusted text snippets."""

    snippets: list[tuple[str, str]] = field(default_factory=list)   # (tag, text)

    def add(self, trust: list[str] | None, result: dict[str, Any]) -> None:
        if not trust:
            return
        untrusted = [t for t in trust if isinstance(t, str) and t.startswith("untrusted")]
        if not untrusted:
            return
        # Pull every string field out of the result (bodies, hidden_text, html_comments, etc.)
        pieces: list[str] = []
        _flatten_strings(result, pieces)
        tag = ",".join(untrusted)
        for p in pieces:
            if p and len(p) >= MIN_MATCH_LEN:
                self.snippets.append((tag, p))

    def find_source(self, needle: str) -> str | None:
        """Return the first untrusted-tag whose snippet contains `needle`."""
        if not needle or len(needle) < MIN_MATCH_LEN:
            return None
        n = needle.lower()
        for tag, text in self.snippets:
            if n in text.lower():
                return tag
        return None


def _flatten_strings(obj: Any, out: list[str]) -> None:
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_strings(v, out)


# What counts as "high risk" for taint purposes.
HIGH_RISK = {"pay", "send_email", "read_file"}


def check(store: TaintStore, world: World, tool: str, args: dict[str, Any]) -> Decision:
    if tool not in HIGH_RISK:
        return Decision("pass", "taint")

    allowlist = _trusted_values(world)

    # Flag the SPECIFIC argument that was tainted.
    for name, val in args.items():
        if not isinstance(val, (str, int, float)):
            continue
        sval = str(val)
        if len(sval) < MIN_MATCH_LEN:
            continue
        # Whitelist: values that match trusted world state are not taint-driven,
        # even if the same string also appears in untrusted content.
        if sval in allowlist:
            continue
        src = store.find_source(sval)
        if src:
            return Decision(
                "block", "taint",
                f"{tool}.{name}='{sval}' matches untrusted content from {src}",
            )

    return Decision("pass", "taint")
