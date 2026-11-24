"""Provider registry and a failover provider that tries several in order."""

from __future__ import annotations

from typing import List

from ..config import AIConfig
from .base import AIProvider, NullProvider, PayloadRequest
from .providers import AnthropicProvider, OllamaProvider, OpenAIProvider

_PROVIDERS = {
    "null": NullProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}


class FailoverProvider(AIProvider):
    """Try each wrapped provider until one returns payloads."""

    name = "failover"

    def __init__(self, providers: List[AIProvider]) -> None:
        self.providers = providers or [NullProvider()]

    async def generate(self, request: PayloadRequest) -> List[str]:
        for provider in self.providers:
            try:
                payloads = await provider.generate(request)
            except Exception:  # noqa: BLE001 - one bad provider shouldn't abort
                continue
            if payloads:
                return payloads
        return []

    async def aclose(self) -> None:
        for p in self.providers:
            await p.aclose()


def build_provider(config: AIConfig) -> AIProvider:
    """Instantiate a provider (or NullProvider) from config."""
    if not config.enabled:
        return NullProvider()
    name = (config.provider or "null").lower()
    cls = _PROVIDERS.get(name)
    if cls is None or cls is NullProvider:
        return NullProvider()
    kwargs = {}
    if config.model:
        kwargs["model"] = config.model
    if config.api_key_env:
        kwargs["api_key_env"] = config.api_key_env
    if config.base_url:
        kwargs["base_url"] = config.base_url
    try:
        return cls(**kwargs)
    except TypeError:
        return cls()


def available_providers() -> List[str]:
    return list(_PROVIDERS)
