"""Plugin framework.

A plugin implements one category of check. Plugins are registered by name and
discovered automatically. Each plugin declares whether it is *passive* (only
inspects responses already fetched) or *active* (issues additional requests).

Writing a plugin is intentionally small:

    from panoptes.plugins.base import Plugin, register

    @register
    class MyCheck(Plugin):
        name = "my-check"
        passive = True
        async def check(self, ctx):
            if ...:
                ctx.report(title="...", severity=Severity.LOW, ...)
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

import httpx

from ..http_client import ScopedHttpClient
from ..models import Confidence, Finding, Severity


@dataclass
class ScanContext:
    """Everything a plugin needs for one target URL."""

    url: str
    client: ScopedHttpClient
    response: Optional[httpx.Response] = None  # primary GET of this url
    ai: Optional["object"] = None  # AIProvider; typed loosely to avoid import cycle
    _findings: List[Finding] = field(default_factory=list)

    def report(
        self,
        *,
        plugin: str,
        title: str,
        severity: Severity,
        description: str,
        confidence: Confidence = Confidence.FIRM,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
        evidence: str = "",
        remediation: str = "",
        references: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        url: Optional[str] = None,
    ) -> Finding:
        finding = Finding(
            plugin=plugin,
            title=title,
            severity=severity,
            description=description,
            confidence=confidence,
            cwe=cwe,
            owasp=owasp,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
            tags=tags or [],
            url=url or self.url,
        )
        self._findings.append(finding)
        return finding

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)


class Plugin:
    """Base class for all checks."""

    name: str = ""
    description: str = ""
    passive: bool = True
    severity_hint: Severity = Severity.INFO

    async def check(self, ctx: ScanContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _report(self, ctx: ScanContext, **kwargs) -> Finding:
        kwargs.setdefault("plugin", self.name)
        return ctx.report(**kwargs)


_REGISTRY: Dict[str, Type[Plugin]] = {}


def register(cls: Type[Plugin]) -> Type[Plugin]:
    if not getattr(cls, "name", ""):
        raise ValueError(f"plugin {cls!r} must define a non-empty 'name'")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate plugin name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def discover() -> Dict[str, Type[Plugin]]:
    """Import every sibling module so @register side effects run."""
    package = importlib.import_module(__name__.rsplit(".", 1)[0])
    for mod in pkgutil.iter_modules(package.__path__):
        if mod.name in ("base",):
            continue
        importlib.import_module(f"{package.__name__}.{mod.name}")
    return dict(_REGISTRY)


def registry() -> Dict[str, Type[Plugin]]:
    return dict(_REGISTRY)


def select(
    include: Optional[List[str]] = None, exclude: Optional[List[str]] = None
) -> List[Plugin]:
    """Instantiate the chosen plugins."""
    discover()
    names = list(_REGISTRY)
    if include:
        names = [n for n in names if n in set(include)]
    if exclude:
        names = [n for n in names if n not in set(exclude)]
    return [_REGISTRY[n]() for n in names]
