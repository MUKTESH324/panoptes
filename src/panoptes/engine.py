"""The scan engine: ties scope, crawling, plugins and AI together."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from .ai import AIProvider, build_provider
from .config import Config
from .crawler import Crawler
from .http_client import ScopedHttpClient
from .models import ScanResult
from .plugins.base import Plugin, ScanContext, select
from .scope import Scope
from .utils.dedupe import dedupe_findings
from .utils.urls import hostname

log = logging.getLogger("panoptes.engine")


class Engine:
    def __init__(self, config: Config, scope: Optional[Scope] = None) -> None:
        self.config = config
        self.scope = scope or Scope(
            allow=config.scope.allow or _default_allow(config.target),
            deny=config.scope.deny,
            allow_private=config.scope.allow_private,
            authorized=config.scope.authorized,
        )
        self.plugins: List[Plugin] = select(
            include=config.plugins or None,
            exclude=config.exclude_plugins or None,
        )

    async def run(self) -> ScanResult:
        # Authorization + scope gate. Refuses here if not affirmed.
        self.scope.require_authorization()

        result = ScanResult(target=self.config.target)
        result.meta["plugins"] = [p.name for p in self.plugins]
        provider: AIProvider = build_provider(self.config.ai)
        result.meta["ai_provider"] = provider.name
        result.meta["authenticated"] = self.config.auth.active

        async with ScopedHttpClient(
            self.scope,
            self.config.http,
            auth=self.config.auth,
            cookie_domain=hostname(self.config.target),
        ) as client:
            crawler = Crawler(client, self.scope, self.config.crawl)
            try:
                pages = await crawler.crawl(self.config.target)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"crawl failed: {exc}")
                pages = {}

            if self.config.target not in pages:
                # Ensure the target itself is scanned even if crawl skipped it.
                try:
                    pages[self.config.target] = await client.get(self.config.target)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"could not fetch target: {exc}")

            result.urls_scanned = len(pages)

            for url, response in pages.items():
                ctx = ScanContext(url=url, client=client, response=response, ai=provider)
                await self._run_plugins(ctx, result)

        await provider.aclose()
        result.findings = dedupe_findings(result.findings)
        result.finished_at = __import__("time").time()
        return result

    async def _run_plugins(self, ctx: ScanContext, result: ScanResult) -> None:
        for plugin in self.plugins:
            try:
                await plugin.check(ctx)
            except Exception as exc:  # noqa: BLE001 - isolate plugin failures
                result.errors.append(f"{plugin.name} failed on {ctx.url}: {exc}")
                log.debug("plugin %s failed on %s: %s", plugin.name, ctx.url, exc)
        result.findings.extend(ctx.findings)


def _default_allow(target: str) -> List[str]:
    from urllib.parse import urlsplit

    host = urlsplit(target).hostname
    return [host] if host else []


def scan(config: Config, scope: Optional[Scope] = None) -> ScanResult:
    """Synchronous convenience wrapper around :meth:`Engine.run`."""
    return asyncio.run(Engine(config, scope).run())
