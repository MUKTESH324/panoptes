"""AI provider abstraction.

Panoptes can optionally use an LLM to generate *context-aware* test payloads
(e.g. tailored XSS/SQLi probes given a parameter name and observed tech stack).
Providers share one tiny interface — :meth:`generate` — so the engine is
provider-agnostic and can fail over across several.

No provider is required: the default :class:`NullProvider` returns an empty
list, and Panoptes runs its full static payload set without any API key.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PayloadRequest:
    """A request for AI-generated payloads for one injection context."""

    vuln_type: str              # e.g. "xss", "sqli"
    parameter: str
    url: str
    tech_stack: Optional[str] = None
    waf: Optional[str] = None
    max_payloads: int = 8


class AIProvider(abc.ABC):
    """Base class for LLM providers (payload generation + analysis)."""

    name: str = "base"

    @abc.abstractmethod
    async def generate(self, request: PayloadRequest) -> List[str]:
        """Return a list of candidate payload strings (possibly empty)."""

    async def analyze(self, prompt: str, system: str = "") -> str:
        """Freeform completion used for the AI analyst. Default: no-op."""
        return ""

    async def aclose(self) -> None:  # pragma: no cover - optional override
        return None


class NullProvider(AIProvider):
    """No-op provider used when AI is disabled."""

    name = "null"

    async def generate(self, request: PayloadRequest) -> List[str]:
        return []


SYSTEM_PROMPT = (
    "You are a payload generator for an AUTHORIZED web application security "
    "scanner. Given a vulnerability class, a parameter name and context, return "
    "a concise JSON array of detection payloads (strings only). Payloads must be "
    "non-destructive probes suitable for authorized testing. Return JSON only."
)

ANALYST_SYSTEM = (
    "You are a senior application security analyst reviewing the output of an "
    "AUTHORIZED, non-destructive web vulnerability scan. Given a digest of "
    "findings, write a concise report for the engineering team: an executive "
    "summary, the top risks in priority order with brief rationale, and a short "
    "remediation roadmap. Be factual and do not invent findings beyond the "
    "digest. Do not provide exploitation instructions — focus on risk and fixes. "
    "Plain prose with short headings; no code."
)
