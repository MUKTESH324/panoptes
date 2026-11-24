"""Optional headless-browser crawler (Playwright) for URL discovery.

The default crawler parses static HTML, so it misses links and endpoints that a
single-page app builds with JavaScript. When Playwright is installed and
``crawl.render`` is on, this renders each page in headless Chromium, collects
links from the live DOM *and* the XHR/fetch requests the app makes, and returns
the in-scope URLs it found. Those are then fetched through the normal scoped
HTTP client so every check plugin works on them as usual.

Playwright is an **optional** dependency:

    pip install "panoptes-scanner[browser]"   # or: pip install playwright
    playwright install chromium

If it is not available, :meth:`available` returns False and the hunt continues
with the static crawler plus a note.
"""

from __future__ import annotations

import importlib.util
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .scope import OutOfScopeError, Scope


class BrowserCrawler:
    def __init__(self, scope: Scope, max_pages: int = 40, timeout: float = 15.0) -> None:
        self.scope = scope
        self.max_pages = max_pages
        self.timeout = timeout

    @staticmethod
    def available() -> bool:
        return importlib.util.find_spec("playwright") is not None

    async def discover(
        self, start_url: str, cookies: Optional[Dict[str, str]] = None
    ) -> Tuple[Set[str], List[str]]:
        """Return (in-scope URLs discovered, errors). Never raises."""
        found: Set[str] = set()
        errors: List[str] = []
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:  # noqa: BLE001
            return found, [f"Playwright unavailable: {exc}"]

        origin = _origin(start_url)
        host = urlsplit(start_url).hostname or ""
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    await context.add_cookies(
                        [{"name": k, "value": v, "domain": host, "path": "/"}
                         for k, v in cookies.items()]
                    )
                page = await context.new_page()
                captured: List[str] = []
                page.on("request", lambda req: captured.append(req.url))

                queue: List[str] = [start_url]
                seen: Set[str] = set()
                while queue and len(seen) < self.max_pages:
                    url = queue.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    try:
                        await page.goto(url, wait_until="networkidle",
                                        timeout=int(self.timeout * 1000))
                    except Exception:  # noqa: BLE001 - skip bad page
                        continue
                    try:
                        hrefs = await page.eval_on_selector_all(
                            "a[href]", "els => els.map(e => e.href)")
                    except Exception:  # noqa: BLE001
                        hrefs = []
                    for link in list(hrefs) + captured:
                        if self._in_scope(link):
                            found.add(link)
                            if _origin(link) == origin and link not in seen:
                                queue.append(link)
                    captured.clear()
                await browser.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"browser crawl failed: {exc}")
        return found, errors

    def _in_scope(self, url: str) -> bool:
        try:
            self.scope.check_url(url)
            return True
        except OutOfScopeError:
            return False
        except Exception:  # noqa: BLE001
            return False


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()
