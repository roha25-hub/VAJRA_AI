"""Ask each configured provider what models are available with the current key."""

from __future__ import annotations

import os

import httpx
import yaml
from dotenv import load_dotenv

from llm.gateway import PROJECT_ROOT

load_dotenv()


def main() -> None:
    cfg = yaml.safe_load((PROJECT_ROOT / "config" / "providers.yaml").read_text())
    for name, pc in cfg["providers"].items():
        if name == "ollama":
            continue
        key_env = pc.get("api_key_env")
        key = os.environ.get(key_env or "", "")
        if not key:
            print(f"[{name}] no key in env, skipping")
            continue
        url = pc["base_url"].rstrip("/") + "/models"
        try:
            r = httpx.get(url, headers={"Authorization": f"Bearer {key}"}, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            ids = [m.get("id") for m in data.get("data", [])]
            print(f"[{name}] {len(ids)} models")
            for i in ids[:40]:
                print(f"  - {i}")
            if len(ids) > 40:
                print(f"  ... and {len(ids)-40} more")
        except Exception as e:
            print(f"[{name}] FAILED: {e}")


if __name__ == "__main__":
    main()
