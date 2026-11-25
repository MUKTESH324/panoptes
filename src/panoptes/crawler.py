"""Async, scope-aware crawler.

Breadth-first crawl bounded by depth and a hard URL cap. Links are extracted
from HTML with a small regex (no BeautifulSoup dependency). Every candidate URL
is validated against scope before it is queued or fetched.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from .config import CrawlConfig
from .http_client import ScopedHttpClient
from .scope import OutOfScopeError, Scope

_LINK_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#>\s]+)["']""", re.IGNORECASE
)


class Crawler:
    def __init__(
        self,
        client: ScopedHttpClient,
        scope: Scope,
        config: CrawlConfig,
        relogin=None,
        logged_out_marker: str = "",
    ) -> None:
        self.client = client
        self.scope = scope
        self.config = config
        # Session re-auth: if a page looks logged out and `relogin` is set,
        # call it and retry the request once.
        self.relogin = relogin
        self.logged_out_marker = logged_out_marker
        self.reauth_count = 0

    async def crawl(self, start_url: str) -> Dict[str, httpx.Response]:
        """Return a mapping of discovered in-scope URL -> its GET response."""
        start_origin = _origin(start_url)
        seen: Set[str] = set()
        results: Dict[str, httpx.Response] = {}
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])

        while queue and len(results) < self.config.max_urls:
            url, depth = queue.popleft()
            url, _ = urldefrag(url)
            if url in seen:
                continue
            seen.add(url)

            try:
                resp = await self.client.get(url)
                resp = await self._maybe_reauth(url, resp)
            except OutOfScopeError:
                continue
            except Exception:  # noqa: BLE001 - unreachable page, skip
                continue
            results[url] = resp

            if not self.config.enabled or depth >= self.config.max_depth:
                continue
            if "html" not in resp.headers.get("content-type", "").lower():
                continue

            for link in self._extract_links(url, resp):
                if link in seen:
                    continue
                if self.config.same_origin_only and _origin(link) != start_origin:
                    continue
                try:
                    self.scope.check_url(link)
                except OutOfScopeError:
                    continue
                queue.append((link, depth + 1))

        return results

    async def _maybe_reauth(self, url: str, resp: httpx.Response) -> httpx.Response:
        """If the page looks logged out, re-login and retry once."""
        if not (self.relogin and self.logged_out_marker):
            return resp
        try:
            body = resp.text[:200_000]
        except Exception:  # noqa: BLE001
            return resp
        if self.logged_out_marker not in body:
            return resp
        try:
            await self.relogin()
            self.reauth_count += 1
            return await self.client.get(url)
        except Exception:  # noqa: BLE001
            return resp

    def _extract_links(self, base: str, resp: httpx.Response) -> List[str]:
        try:
            body = resp.text[:1_000_000]
        except Exception:  # noqa: BLE001
            return []
        links: List[str] = []
        for raw in _LINK_RE.findall(body):
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            links.append(urljoin(base, raw))
        return links


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()
