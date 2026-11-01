"""Single LLM gateway. Every model call in the project goes through here.

Per plan §4.1:
  1. OpenAI-compatible interface across providers.
  2. Per-provider rate limiter (RPM / RPD, best-effort local).
  3. Retry with exponential backoff on 429 / 5xx.
  4. Failover across providers for a role, then local (Ollama).
  5. Response cache keyed by hash of (model, messages, temperature, schema).
  6. Record/replay: live mode records, replay mode reads only.
  7. Usage counters per provider per day.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from dotenv import load_dotenv


load_dotenv()

RunMode = Literal["live", "replay", "fresh"]
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ============================================================
# Request / Response
# ============================================================

@dataclass
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    content: str


@dataclass
class ChatRequest:
    role: str                                     # routing key: "target" | "redteam" | "guardian_intent"
    messages: list[Message]
    temperature: float = 0.0
    max_tokens: int = 1024                        # reasoning models (gpt-oss) burn tokens on thought; keep room for actual output
    response_schema: dict[str, Any] | None = None  # JSON-mode schema
    tools: list[dict[str, Any]] | None = None
    tag: str = ""                                  # free-form note for logs


@dataclass
class ChatResponse:
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    cached: bool = False
    usage: dict[str, int] = field(default_factory=dict)


def cache_key(role: str, model: str, messages: list[Message], temperature: float,
              schema: dict[str, Any] | None, tools: list[dict[str, Any]] | None) -> str:
    payload = {
        "role": role, "model": model,
        "messages": [(m.role, m.content) for m in messages],
        "temperature": temperature, "schema": schema, "tools": tools,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


# ============================================================
# Cache (SQLite)
# ============================================================

class _Cache:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("""
            create table if not exists cache(
                key text primary key,
                provider text, model text,
                response_json text not null,
                created_at text not null default (datetime('now'))
            )""")
        self._conn.execute("""
            create table if not exists usage(
                day text, provider text, calls int,
                primary key(day, provider)
            )""")
        self._conn.commit()

    def get(self, key: str) -> ChatResponse | None:
        with self._lock:
            row = self._conn.execute(
                "select response_json, provider, model from cache where key=?", (key,)
            ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        return ChatResponse(cached=True, provider=row[1], model=row[2], **data)

    def put(self, key: str, resp: ChatResponse) -> None:
        payload = json.dumps({
            "content": resp.content,
            "tool_calls": resp.tool_calls,
            "usage": resp.usage,
        })
        with self._lock:
            self._conn.execute(
                "insert or replace into cache(key, provider, model, response_json) values(?,?,?,?)",
                (key, resp.provider, resp.model, payload),
            )
            self._conn.commit()

    def bump_usage(self, provider: str) -> None:
        today = date.today().isoformat()
        with self._lock:
            self._conn.execute(
                "insert into usage(day, provider, calls) values(?,?,1) "
                "on conflict(day, provider) do update set calls = calls + 1",
                (today, provider),
            )
            self._conn.commit()

    def usage_today(self) -> dict[str, int]:
        today = date.today().isoformat()
        with self._lock:
            rows = self._conn.execute(
                "select provider, calls from usage where day=?", (today,)
            ).fetchall()
        return {p: c for p, c in rows}


# ============================================================
# Simple local rate limiter (RPM + RPD)
# ============================================================

class _RateLimiter:
    """Best-effort local limiter. Does NOT replace provider-side quotas."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._minute: dict[str, deque[float]] = {}
        self._day: dict[tuple[str, str], int] = {}
        self._day_date = date.today().isoformat()

    def check(self, provider: str, rpm: int, rpd: int) -> float:
        """Return 0 if OK, else seconds to wait."""
        with self._lock:
            now = time.time()
            today = date.today().isoformat()
            if today != self._day_date:
                self._day.clear()
                self._day_date = today

            q = self._minute.setdefault(provider, deque())
            while q and now - q[0] > 60:
                q.popleft()

            if self._day.get((today, provider), 0) >= rpd:
                return 60.0  # back off a minute; day counter will roll over tomorrow
            if len(q) >= rpm:
                return max(0.1, 60 - (now - q[0]))
            q.append(now)
            self._day[(today, provider)] = self._day.get((today, provider), 0) + 1
            return 0.0


# ============================================================
# Gateway
# ============================================================

class Gateway:
    def __init__(self, cfg: dict[str, Any], mode: RunMode = "live",
                 cache_path: Path | None = None) -> None:
        self.cfg = cfg
        self.mode: RunMode = mode
        cp = cache_path or (PROJECT_ROOT / "llm" / "cache.sqlite")
        self.cache = _Cache(cp)
        self.limiter = _RateLimiter()
        self._client = httpx.Client(timeout=60.0)

    # ---- construction ----

    @classmethod
    def from_config(cls, path: str | Path | None = None,
                    mode: RunMode | None = None) -> "Gateway":
        p = Path(path) if path else (PROJECT_ROOT / "config" / "providers.yaml")
        cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
        m: RunMode = mode or os.environ.get("AEGIS_RUN_MODE", "live")  # type: ignore[assignment]
        return cls(cfg, mode=m)

    # ---- public ----

    def chat(self, req: ChatRequest) -> ChatResponse:
        chain = self.cfg["roles"].get(req.role)
        if not chain:
            raise ValueError(f"no provider chain configured for role '{req.role}'")

        first_model = chain[0]["model"]
        key = cache_key(req.role, first_model, req.messages, req.temperature,
                        req.response_schema, req.tools)

        if self.mode != "fresh":
            hit = self.cache.get(key)
            if hit is not None:
                return hit

        if self.mode == "replay":
            raise RuntimeError(f"replay miss for key {key[:12]}... (role={req.role})")

        # Outer retry: if every provider is JUST rate-limited (not errored), sleep
        # and retry the chain rather than giving up. Caps total wait so we don't
        # hang forever.
        total_waited = 0.0
        max_wait_total = 180.0
        while True:
            errors: list[str] = []
            min_rate_wait = 1e9
            for provider_cfg in chain:
                name = provider_cfg["provider"]
                model = provider_cfg["model"]
                rpm = int(provider_cfg.get("rpm", 60))
                rpd = int(provider_cfg.get("rpd", 1000))

                wait = self.limiter.check(name, rpm, rpd)
                if wait > 0:
                    min_rate_wait = min(min_rate_wait, wait)
                    errors.append(f"{name}: rate-limited (~{wait:.0f}s)")
                    continue

                try:
                    resp = self._call_openai_compat(name, model, req)
                    self.cache.put(key, resp)
                    self.cache.bump_usage(name)
                    return resp
                except (httpx.HTTPError, RuntimeError) as e:
                    errors.append(f"{name}: {e}")
                    continue

            # If ANY provider errored (not just rate-limited), surface the chain failure.
            all_rate_limited = all("rate-limited" in e for e in errors) and errors
            if all_rate_limited and total_waited < max_wait_total:
                nap = min(min_rate_wait + 0.5, 15.0)
                time.sleep(nap)
                total_waited += nap
                continue

            detail = " | ".join(errors) if errors else "no providers tried"
            raise RuntimeError(f"all providers failed for role '{req.role}': {detail}")

    def usage_today(self) -> dict[str, int]:
        return self.cache.usage_today()

    # ---- provider calls ----

    def _call_openai_compat(self, provider: str, model: str, req: ChatRequest) -> ChatResponse:
        prov_cfg = self.cfg["providers"][provider]
        base = prov_cfg["base_url"].rstrip("/")
        key_env = prov_cfg.get("api_key_env")
        headers = {"Content-Type": "application/json"}
        if key_env:
            api_key = os.environ.get(key_env, "")
            if not api_key:
                raise RuntimeError(f"missing env var {key_env} for provider {provider}")
            headers["Authorization"] = f"Bearer {api_key}"

        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
        # Groq gpt-oss models are reasoning models; cap internal thought budget
        # so completion tokens aren't entirely burned on reasoning.
        if provider == "groq" and model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"
        if req.response_schema is not None:
            body["response_format"] = {"type": "json_object"}  # most OpenAI-compat providers accept this
        if req.tools:
            body["tools"] = [{"type": "function", "function": t} for t in req.tools]

        # Retry with backoff on 429 / 5xx. Honor Retry-After when present.
        for attempt in range(3):
            try:
                r = self._client.post(f"{base}/chat/completions", headers=headers, json=body)
            except httpx.ConnectError as e:
                # Ollama not running, etc. Don't crash; let outer failover try next provider.
                raise RuntimeError(f"{provider} unreachable: {e}")
            if r.status_code == 200:
                break
            if r.status_code in (429, 500, 502, 503, 504):
                ra = r.headers.get("retry-after")
                try:
                    delay = float(ra) if ra else 1.5 ** attempt
                except ValueError:
                    delay = 1.5 ** attempt
                time.sleep(min(delay, 10.0))
                continue
            raise RuntimeError(f"{provider} HTTP {r.status_code}: {r.text[:300]}")
        else:
            raise RuntimeError(f"{provider} exhausted retries")

        data = r.json()
        choice = data["choices"][0]["message"]
        content = choice.get("content") or ""
        # Reasoning models (Groq gpt-oss) may put the actual answer in `reasoning`
        # when content is cut off. Fall back to that so the caller sees something.
        if not content and choice.get("reasoning"):
            content = choice["reasoning"]
        tool_calls_raw = choice.get("tool_calls") or []
        tool_calls = []
        for tc in tool_calls_raw:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append({"name": fn.get("name"), "args": args})

        usage = data.get("usage") or {}
        return ChatResponse(
            content=content, tool_calls=tool_calls,
            provider=provider, model=model, cached=False,
            usage={
                "prompt_tokens": int(usage.get("prompt_tokens", 0)),
                "completion_tokens": int(usage.get("completion_tokens", 0)),
            },
        )

    def close(self) -> None:
        self._client.close()
