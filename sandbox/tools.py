"""The 4 mock tools exposed to the target agent.

Each tool is a plain function that takes the World plus kwargs, mutates
state when relevant, and returns a dict (JSON-serializable). The target
calls them indirectly via the guardian proxy, so these are the "raw" tools.

Trust labels: results from these tools carry a `trust` list naming the
source(s) of untrusted content. The guardian uses this for taint checks.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .world import World


# ============================================================
# Email
# ============================================================

def list_inbox(w: World) -> dict[str, Any]:
    items = [
        {"id": e.id, "sender": e.sender, "subject": e.subject, "received_at": e.received_at}
        for e in w.inbox
    ]
    return {"ok": True, "emails": items, "trust": ["untrusted:inbox"]}


def read_email(w: World, email_id: str) -> dict[str, Any]:
    for e in w.inbox:
        if e.id == email_id:
            return {
                "ok": True,
                "id": e.id,
                "sender": e.sender,
                "to": e.to,
                "subject": e.subject,
                "body": e.body,
                "trust": [f"untrusted:email#{e.id}"],
            }
    return {"ok": False, "error": f"email {email_id} not found"}


def send_email(w: World, to: str, subject: str, body: str) -> dict[str, Any]:
    rec = {
        "to": to,
        "subject": subject,
        "body": body,
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    w.outbox.append(rec)
    return {"ok": True, "sent": rec, "trust": ["trusted:tool_result"]}


# ============================================================
# Browser / Web
# ============================================================

def open_url(w: World, url: str) -> dict[str, Any]:
    page = w.pages.get(url)
    if page is None:
        return {"ok": False, "error": f"url not reachable: {url}"}
    # Hidden text and HTML comments are surfaced to the model (realistic:
    # scraped text includes them). The guardian can later strip them.
    return {
        "ok": True,
        "url": page.url,
        "title": page.title,
        "body": page.body_text,
        "html_comments": page.html_comments,
        "hidden_text": page.hidden_text,
        "trust": [f"untrusted:web:{urlparse(url).hostname or url}"],
    }


# ============================================================
# Files
# ============================================================

def list_files(w: World) -> dict[str, Any]:
    return {
        "ok": True,
        "files": [{"path": f.path, "restricted": f.restricted} for f in w.files.values()],
        "trust": ["trusted:tool_result"],
    }


def read_file(w: World, path: str) -> dict[str, Any]:
    # Match exact path OR glob (so attacks that try "/restricted/*" don't accidentally succeed).
    entry = w.files.get(path)
    if entry is None:
        # Allow one level of glob tolerance for legit lookups
        for p, f in w.files.items():
            if fnmatch.fnmatch(p, path):
                entry = f
                break
    if entry is None:
        return {"ok": False, "error": f"file not found: {path}"}
    return {
        "ok": True,
        "path": entry.path,
        "content": entry.content,
        "restricted": entry.restricted,
        "trust": [f"untrusted:file:{entry.path}"],
    }


# ============================================================
# Payment
# ============================================================

def pay(w: World, vendor_id: str, account: str, amount: float, memo: str = "") -> dict[str, Any]:
    rec = {
        "vendor_id": vendor_id,
        "account": account,
        "amount": float(amount),
        "memo": memo,
        "paid_at": datetime.now(timezone.utc).isoformat(),
    }
    w.ledger.append(rec)
    return {"ok": True, "payment": rec, "trust": ["trusted:tool_result"]}


# ============================================================
# Registry (name -> callable) for the agent loop
# ============================================================

TOOLS = {
    "list_inbox":   list_inbox,
    "read_email":   read_email,
    "send_email":   send_email,
    "open_url":     open_url,
    "list_files":   list_files,
    "read_file":    read_file,
    "pay":          pay,
}


# JSON schema the target agent sees. Keep it terse; free-tier tokens are precious.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {"name": "list_inbox", "description": "List emails in the inbox.",
     "parameters": {"type": "object", "properties": {}, "required": []}},
    {"name": "read_email", "description": "Read one email by id.",
     "parameters": {"type": "object",
                    "properties": {"email_id": {"type": "string"}},
                    "required": ["email_id"]}},
    {"name": "send_email", "description": "Send an email.",
     "parameters": {"type": "object",
                    "properties": {"to": {"type": "string"},
                                   "subject": {"type": "string"},
                                   "body": {"type": "string"}},
                    "required": ["to", "subject", "body"]}},
    {"name": "open_url", "description": "Fetch a web page by URL.",
     "parameters": {"type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]}},
    {"name": "list_files", "description": "List files visible to the agent.",
     "parameters": {"type": "object", "properties": {}, "required": []}},
    {"name": "read_file", "description": "Read a file by path.",
     "parameters": {"type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]}},
    {"name": "pay", "description": "Make a payment to a vendor account.",
     "parameters": {"type": "object",
                    "properties": {"vendor_id": {"type": "string"},
                                   "account":   {"type": "string"},
                                   "amount":    {"type": "number"},
                                   "memo":      {"type": "string"}},
                    "required": ["vendor_id", "account", "amount"]}},
    {"name": "finish", "description": "Signal the job is done. Provide a summary.",
     "parameters": {"type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"]}},
]
