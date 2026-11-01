"""Layer 1: deterministic policy rules (plan §6.5.2).

Reads config/policies.json and enforces hard constraints per task:
  - allowed tools
  - pay: cap, approved vendors, approved account match, PO match
  - send_email: allowed domains
  - read_file: deny glob
  - open_url: allowed hosts
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sandbox.world import World

from .decisions import Decision


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_policy(task: str = "process_invoices", path: Path | None = None) -> dict[str, Any]:
    p = path or (PROJECT_ROOT / "config" / "policies.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    return data["tasks"][task]


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


def check(policy: dict[str, Any], world: World, tool: str, args: dict[str, Any]) -> Decision:
    allowed_tools = policy.get("allowed_tools", []) + ["finish", "list_inbox", "list_files"]
    if tool not in allowed_tools:
        return Decision("block", "policy", f"tool '{tool}' not in allowed list")

    if tool == "pay":
        pay = policy.get("pay", {})
        vid = args.get("vendor_id", "")
        acct = args.get("account", "")
        amt = float(args.get("amount", 0) or 0)
        memo = args.get("memo", "")

        if vid not in pay.get("allowed_vendors", []):
            return Decision("block", "policy", f"vendor '{vid}' not approved")
        if amt > float(pay.get("max_amount", 0)):
            return Decision("block", "policy", f"amount ${amt} exceeds cap ${pay['max_amount']}")

        vendor = world.vendors.get(vid)
        if vendor and vendor.approved_account and acct != vendor.approved_account:
            return Decision("block", "policy",
                            f"account '{acct}' is not the approved account for {vid}")

        if pay.get("require_po_match"):
            # Memo may contain the invoice ref as a substring (e.g. "Invoice INV-2041").
            matching = [po for po in world.pos.values()
                        if po.vendor_id == vid
                        and (po.invoice_ref in memo or po.po_id in memo)]
            if not matching:
                return Decision("block", "policy", f"no PO matches memo '{memo}' for {vid}")
            if matching[0].amount * 1.01 < amt:
                return Decision("block", "policy",
                                f"amount ${amt} exceeds PO ${matching[0].amount}")

    if tool == "send_email":
        allowed = set(policy.get("send_email", {}).get("allowed_domains", []))
        dom = _domain(args.get("to", ""))
        if allowed and dom not in allowed:
            return Decision("block", "policy", f"domain '{dom}' not on allowlist")

    if tool == "read_file":
        for pat in policy.get("read_file", {}).get("deny_paths", []):
            if fnmatch.fnmatch(args.get("path", ""), pat):
                return Decision("block", "policy", f"path matches deny pattern '{pat}'")

    if tool == "open_url":
        allowed = set(policy.get("open_url", {}).get("allowed_hosts", []))
        host = urlparse(args.get("url", "")).hostname or ""
        if allowed and host not in allowed:
            return Decision("block", "policy", f"host '{host}' not on allowlist")

    return Decision("pass", "policy")
