"""Concrete AI providers (OpenAI-compatible, Anthropic, Ollama).

All providers talk HTTP directly via httpx so Panoptes has no heavy vendor SDK
dependencies. Payloads are parsed defensively: anything that is not a clean
JSON array of strings is discarded.
"""

from __future__ import annotations

import json
import os
import re
from typing import List

import httpx

from .base import SYSTEM_PROMPT, AIProvider, PayloadRequest


def _parse_payloads(text: str, limit: int) -> List[str]:
    """Extract a JSON array of strings from a model response."""
    text = text.strip()
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    out = [str(x) for x in data if isinstance(x, (str, int, float))]
    # De-dupe preserving order, cap length.
    seen = set()
    result = []
    for p in out:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result[:limit]


def _user_prompt(req: PayloadRequest) -> str:
    ctx = [f"vulnerability class: {req.vuln_type}", f"parameter: {req.parameter}", f"url: {req.url}"]
    if req.tech_stack:
        ctx.append(f"tech stack: {req.tech_stack}")
    if req.waf:
        ctx.append(f"waf: {req.waf}")
    ctx.append(f"return at most {req.max_payloads} payloads as a JSON array of strings")
    return "\n".join(ctx)


class OpenAIProvider(AIProvider):
    """Works with OpenAI and any OpenAI-compatible /chat/completions endpoint."""

    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", api_key_env: str = "OPENAI_API_KEY", base_url: str = "https://api.openai.com/v1") -> None:
        self.model = model or "gpt-4o-mini"
        self.api_key = os.getenv(api_key_env or "OPENAI_API_KEY", "")
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")

    async def generate(self, request: PayloadRequest) -> List[str]:
        if not self.api_key:
            return []
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(request)},
            ],
            "temperature": 0.4,
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
        return _parse_payloads(content, request.max_payloads)


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def __init__(self, model: str = "claude-haiku-5-5", api_key_env: str = "ANTHROPIC_API_KEY", base_url: str = "https://api.anthropic.com/v1") -> None:
        self.model = model or "claude-haiku-5-5"
        self.api_key = os.getenv(api_key_env or "ANTHROPIC_API_KEY", "")
        self.base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")

    async def generate(self, request: PayloadRequest) -> List[str]:
        if not self.api_key:
            return []
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": _user_prompt(request)}],
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
                json=payload,
            )
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            content = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return _parse_payloads(content, request.max_payloads)


class OllamaProvider(AIProvider):
    """Local models via Ollama — no API key, nothing leaves the host."""

    name = "ollama"

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434", **_: object) -> None:
        self.model = model or "llama3"
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")

    async def generate(self, request: PayloadRequest) -> List[str]:
        payload = {
            "model": self.model,
            "prompt": SYSTEM_PROMPT + "\n\n" + _user_prompt(request),
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                resp.raise_for_status()
                content = resp.json().get("response", "")
        except Exception:  # noqa: BLE001 - local daemon may be down
            return []
        return _parse_payloads(content, request.max_payloads)
