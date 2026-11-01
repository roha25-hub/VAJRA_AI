"""Live connectivity check for the LLM gateway.

Hits whatever provider chain is configured for the role. Prints which
provider answered, token usage, and whether the second call was served
from cache (should be).

Run:  python scripts/check_gateway.py
"""

from __future__ import annotations

import sys

from llm.gateway import ChatRequest, Gateway, Message


def ping(role: str) -> None:
    gw = Gateway.from_config()
    req = ChatRequest(
        role=role,
        messages=[
            Message("system", "You are a terse echo bot."),
            Message("user", "Reply with the single word PONG and nothing else."),
        ],
        max_tokens=256,
    )
    r1 = gw.chat(req)
    r2 = gw.chat(req)   # should be cached
    print(f"[{role}] provider={r1.provider} model={r1.model} cached={r1.cached} "
          f"content={r1.content!r} usage={r1.usage}")
    print(f"[{role}] second call cached={r2.cached}")
    print(f"usage today: {gw.usage_today()}")
    gw.close()


if __name__ == "__main__":
    roles = sys.argv[1:] or ["target", "redteam"]
    for role in roles:
        try:
            ping(role)
        except Exception as e:
            print(f"[{role}] FAILED: {e}")
