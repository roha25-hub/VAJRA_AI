"""Shared decision types used by every guardian layer.

Each layer returns a Decision; the proxy stops at the first non-ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Verdict = Literal["allow", "block", "escalate", "pass"]
# "pass" = this layer has no opinion; try the next layer.
# "allow"/"block"/"escalate" are final.


@dataclass
class Decision:
    verdict: Verdict
    layer: str
    reason: str = ""
