"""Specialist base class + shared hardening.

Each specialist is an ADVISOR, not a decider. The orchestrator still
owns the final allow/deny via union-deny over specialist votes AND the
deterministic policy wall below it.

Hardening baked into the base class so every specialist gets it for free:

  - **Function-level throttling**: per-tool call-rate caps (e.g. max 3
    pay() calls per minute) regardless of who asks.
  - **Behavioral throttling**: per-source rolling-window burst limit;
    if ONE untrusted source is driving a spike in tool calls, hard-deny.
  - **Rate limit**: cap per specialist per second to protect the LLM
    tier; excess calls auto-deny (fail-safe).
  - **Trace lock**: every decision gets appended immutably with a
    monotonic index + HMAC so a compromised specialist cannot rewrite
    earlier decisions.
  - **Signed envelopes**: specialists sign their SpecialistReply with a
    per-process secret; orchestrator verifies before counting a vote.
    Stops role-confusion attacks across agents.
  - **No cached allow**: deny decisions may be cached; allow decisions
    never are. Prevents cache-poisoning amplification.
"""
from __future__ import annotations

import hmac
import hashlib
import os
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, ClassVar

from agents.guardian.decisions import Decision

# One shared signing secret per process; rotated on restart.
_AGENT_SECRET = os.urandom(32)


@dataclass
class SpecialistRequest:
    """What the orchestrator sends to a specialist."""
    tool: str
    args: dict[str, Any]
    source_trust: str                   # 'trusted' | 'untrusted' | 'mixed'
    source_id: str                      # which upstream source caused this call
    world_snapshot: dict[str, Any]      # minimal state view; NOT raw world


@dataclass
class SpecialistReply:
    """What a specialist returns."""
    vote: str                           # 'allow' | 'block' | 'abstain'
    reason: str
    specialist: str
    latency_ms: float
    signature: str = ""                 # HMAC over (specialist, vote, reason)

    def is_authentic(self) -> bool:
        exp = hmac.new(_AGENT_SECRET,
                       f"{self.specialist}|{self.vote}|{self.reason}".encode(),
                       hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(self.signature, exp)


# ---------------------------------------------------------------
# Rolling-window throttle (shared across specialists)
# ---------------------------------------------------------------
class _RollingThrottle:
    """Count events in a sliding window; True if under cap."""
    def __init__(self, cap: int, window_s: float) -> None:
        self.cap = cap
        self.window_s = window_s
        self._times: deque[float] = deque()
        self._lock = Lock()

    def allow(self) -> bool:
        now = time.time()
        with self._lock:
            while self._times and now - self._times[0] > self.window_s:
                self._times.popleft()
            if len(self._times) >= self.cap:
                return False
            self._times.append(now)
            return True


# ---------------------------------------------------------------
# Trace lock: append-only decision log with monotonic index + HMAC
# ---------------------------------------------------------------
class TraceLock:
    """Append-only log; nothing can be rewritten in place."""
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._lock = Lock()
        self._index = 0

    def append(self, entry: dict[str, Any]) -> int:
        with self._lock:
            idx = self._index
            prev = self._entries[-1]["sig"] if self._entries else "genesis"
            payload = f"{idx}|{entry}|{prev}".encode()
            sig = hmac.new(_AGENT_SECRET, payload, hashlib.sha256).hexdigest()[:16]
            full = {**entry, "idx": idx, "sig": sig}
            self._entries.append(full)
            self._index += 1
            return idx

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._entries)


# ---------------------------------------------------------------
# BaseSpecialist
# ---------------------------------------------------------------
@dataclass
class BaseSpecialist:
    """Inherit and override `analyze()` to implement a specialist."""

    name: ClassVar[str] = "base"
    handles_tools: ClassVar[tuple[str, ...]] = ()

    # Function-level throttle: tool -> (cap, window_s)
    tool_caps: ClassVar[dict[str, tuple[int, float]]] = {}

    # Per-specialist rate limit: calls per second
    rate_per_sec: ClassVar[int] = 20

    # Behavioral throttle: block an untrusted source after N calls in window
    behavior_cap: ClassVar[int] = 25
    behavior_window_s: ClassVar[float] = 10.0

    # Internal state
    _tool_throttles: dict[str, _RollingThrottle] = field(default_factory=dict)
    _source_throttles: dict[str, _RollingThrottle] = field(default_factory=dict)
    _global_throttle: _RollingThrottle | None = None
    _deny_cache: dict[str, SpecialistReply] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._global_throttle = _RollingThrottle(self.rate_per_sec, 1.0)
        for t, (cap, win) in self.tool_caps.items():
            self._tool_throttles[t] = _RollingThrottle(cap, win)

    # ---- hardening gates ------------------------------------------------
    def _check_rate(self) -> SpecialistReply | None:
        if self._global_throttle and not self._global_throttle.allow():
            return self._reply("block", "rate_limit: specialist overloaded")
        return None

    def _check_function_cap(self, tool: str) -> SpecialistReply | None:
        th = self._tool_throttles.get(tool)
        if th and not th.allow():
            return self._reply("block", f"function_throttle: {tool} cap exceeded")
        return None

    def _check_behavior(self, source_id: str, trust: str) -> SpecialistReply | None:
        if trust != "untrusted":
            return None
        th = self._source_throttles.setdefault(
            source_id, _RollingThrottle(self.behavior_cap, self.behavior_window_s))
        if not th.allow():
            return self._reply("block", f"behavioral_throttle: source {source_id} spiking")
        return None

    def _cache_key(self, req: SpecialistRequest) -> str:
        return f"{req.tool}|{sorted(req.args.items())}|{req.source_id}"

    # ---- envelope -------------------------------------------------------
    def _reply(self, vote: str, reason: str, latency_ms: float = 0.0) -> SpecialistReply:
        r = SpecialistReply(vote=vote, reason=reason, specialist=self.name,
                            latency_ms=latency_ms)
        r.signature = hmac.new(
            _AGENT_SECRET,
            f"{r.specialist}|{r.vote}|{r.reason}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        return r

    # ---- public entry point --------------------------------------------
    def consider(self, req: SpecialistRequest) -> SpecialistReply:
        if req.tool not in self.handles_tools:
            return self._reply("abstain", "not my tool")

        # Hardening gates — any trip = block
        for gate in (self._check_rate(),
                     self._check_function_cap(req.tool),
                     self._check_behavior(req.source_id, req.source_trust)):
            if gate is not None:
                return gate

        # Deny-cache fast path (allow is never cached)
        key = self._cache_key(req)
        cached = self._deny_cache.get(key)
        if cached:
            return cached

        t0 = time.time()
        try:
            reply = self.analyze(req)
        except Exception as e:
            reply = self._reply("block", f"specialist error: {str(e)[:120]}")
        reply.latency_ms = round((time.time() - t0) * 1000, 2)

        # Resign (latency_ms isn't in signature; vote/reason are)
        reply.signature = hmac.new(
            _AGENT_SECRET,
            f"{reply.specialist}|{reply.vote}|{reply.reason}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        if reply.vote == "block":
            self._deny_cache[key] = reply
        return reply

    # ---- subclass contract ----------------------------------------------
    def analyze(self, req: SpecialistRequest) -> SpecialistReply:
        """Override. Return allow/block/abstain. Must not touch I/O."""
        return self._reply("abstain", "base specialist")


def to_decision(reply: SpecialistReply, layer: str) -> Decision:
    """Translate a SpecialistReply into the Decision shape the proxy uses."""
    verdict = "block" if reply.vote == "block" else "pass"
    return Decision(verdict, layer, f"[{reply.specialist}] {reply.reason}")
