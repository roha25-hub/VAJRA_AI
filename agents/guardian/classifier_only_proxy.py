"""A proxy variant that uses ONLY the classifier (plus the raw tool call).

Used for the improvement-curve demo: so the measured round-over-round change
reflects the CLASSIFIER learning, not the hard-coded policy and taint rules
which are static.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sandbox.tools import TOOLS
from sandbox.world import World

from . import detector as detector_layer
from . import taint as taint_layer
from .decisions import Decision


@dataclass
class ClassifierOnlyProxy:
    taint: taint_layer.TaintStore = field(default_factory=taint_layer.TaintStore)
    trace: list[Any] = field(default_factory=list)   # kept generic to match API

    def __call__(self, world: World, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        from .proxy import ProxyTrace  # avoid cycle

        if tool not in detector_layer.HIGH_RISK:
            decision = Decision("allow", "classifier_only")
        else:
            snippets = [t for _tag, t in self.taint.snippets]
            d = detector_layer.check(snippets, tool, args)
            decision = d if d.verdict != "pass" else Decision("allow", "classifier_only")

        self.trace.append(ProxyTrace(tool=tool, args=dict(args), decision=decision))

        if decision.verdict == "block":
            return {"ok": False, "blocked": True,
                    "error": f"blocked by classifier: {decision.reason}",
                    "trust": ["trusted:guardian"]}

        fn = TOOLS.get(tool)
        if fn is None:
            return {"ok": False, "error": f"unknown tool: {tool}"}
        try:
            result = fn(world, **args)
        except TypeError as e:
            return {"ok": False, "error": f"bad args for {tool}: {e}"}

        if isinstance(result, dict):
            self.taint.add(result.get("trust"), result)
            self.trace[-1].result = result
        return result
