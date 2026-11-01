"""Dump the full JSON response from one provider for debugging."""

from __future__ import annotations

import json
import os
import sys

import httpx
import yaml
from dotenv import load_dotenv

from llm.gateway import PROJECT_ROOT

load_dotenv()


def probe(provider: str, model: str) -> None:
    cfg = yaml.safe_load((PROJECT_ROOT / "config" / "providers.yaml").read_text())
    pc = cfg["providers"][provider]
    url = pc["base_url"].rstrip("/") + "/chat/completions"
    key = os.environ[pc["api_key_env"]]
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a terse echo bot."},
            {"role": "user", "content": "Reply with the single word PONG and nothing else."},
        ],
        "temperature": 0,
        "max_tokens": 32,
    }
    r = httpx.post(url, headers={"Authorization": f"Bearer {key}"}, json=body, timeout=30)
    print(f"[{provider}/{model}] status={r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2)[:2000])
    except Exception:
        print(r.text[:2000])


if __name__ == "__main__":
    args = sys.argv[1:] or ["groq", "openai/gpt-oss-20b"]
    probe(args[0], args[1])
