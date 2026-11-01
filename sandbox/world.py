"""The sandbox world: in-memory, deterministic, reset between runs.

Everything the mock tools read/write lives here. Fixtures load from
`config/scenarios/<name>/`. No network, no filesystem writes outside
the project.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCENARIO_ROOT = Path(__file__).resolve().parents[1] / "config" / "scenarios"


@dataclass
class Email:
    id: str
    sender: str
    to: str
    subject: str
    body: str
    received_at: str
    trust: str = "untrusted"  # emails from outside the org


@dataclass
class WebPage:
    url: str
    title: str
    body_text: str
    html_comments: list[str] = field(default_factory=list)
    hidden_text: list[str] = field(default_factory=list)
    trust: str = "untrusted"


@dataclass
class FileEntry:
    path: str
    content: str
    restricted: bool = False
    trust: str = "untrusted"


@dataclass
class Vendor:
    vendor_id: str
    name: str
    approved_account: str
    domain: str
    approved: bool = True


@dataclass
class PurchaseOrder:
    po_id: str
    vendor_id: str
    amount: float
    invoice_ref: str
    paid: bool = False


@dataclass
class World:
    """Mutable sandbox state. One instance per run."""

    inbox: list[Email] = field(default_factory=list)
    outbox: list[dict[str, Any]] = field(default_factory=list)
    pages: dict[str, WebPage] = field(default_factory=dict)
    files: dict[str, FileEntry] = field(default_factory=dict)
    vendors: dict[str, Vendor] = field(default_factory=dict)
    pos: dict[str, PurchaseOrder] = field(default_factory=dict)
    ledger: list[dict[str, Any]] = field(default_factory=list)
    canaries: dict[str, str] = field(default_factory=dict)   # name -> secret value
    attacker_account: str = "999-DEADBEEF"

    def reset(self) -> None:
        self.inbox.clear()
        self.outbox.clear()
        self.pages.clear()
        self.files.clear()
        self.vendors.clear()
        self.pos.clear()
        self.ledger.clear()
        self.canaries.clear()


def load_scenario(name: str = "default") -> World:
    """Build a fresh World from `config/scenarios/<name>/*.json`."""
    root = SCENARIO_ROOT / name
    if not root.exists():
        raise FileNotFoundError(f"scenario not found: {root}")

    w = World()

    def _load(fname: str) -> Any:
        p = root / fname
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []

    for e in _load("inbox.json"):
        w.inbox.append(Email(**e))
    for p in _load("pages.json"):
        w.pages[p["url"]] = WebPage(**p)
    for f in _load("files.json"):
        w.files[f["path"]] = FileEntry(**f)
    for v in _load("vendors.json"):
        w.vendors[v["vendor_id"]] = Vendor(**v)
    for po in _load("purchase_orders.json"):
        w.pos[po["po_id"]] = PurchaseOrder(**po)
    canaries = _load("canaries.json") or {}
    if isinstance(canaries, dict):
        w.canaries.update(canaries)

    return w
