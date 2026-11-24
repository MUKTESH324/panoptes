"""Rate-limited, scope-aware async HTTP client.

Wraps ``httpx.AsyncClient`` with:
  * a token-bucket rate limiter (requests_per_second),
  * a concurrency semaphore,
  * mandatory scope enforcement on every request,
  * simple retry with backoff.

Every outbound request passes through :meth:`Scope.check_url`, so a plugin can
never reach a host that is out of scope, even accidentally.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx

from .config import AuthConfig, HttpConfig
from .scope import Scope


class RateLimiter:
    """Simple async token bucket."""

    def __init__(self, rate: float, burst: Optional[float] = None) -> None:
        self.rate = max(rate, 0.01)
        self.capacity = burst if burst is not None else max(rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)


class ScopedHttpClient:
    """Async HTTP client that enforces scope and rate limits."""

    def __init__(
        self,
        scope: Scope,
        config: Optional[HttpConfig] = None,
        auth: Optional[AuthConfig] = None,
        cookie_domain: Optional[str] = None,
    ) -> None:
        self.scope = scope
        self.config = config or HttpConfig()
        self.auth = auth or AuthConfig()
        # Cookies are bound to this host so they never travel to another domain.
        self.cookie_domain = cookie_domain
        self._limiter = RateLimiter(self.config.requests_per_second)
        self._sem = asyncio.Semaphore(self.config.max_concurrency)
        self._client: Optional[httpx.AsyncClient] = None

    def _build_cookies(self) -> httpx.Cookies:
        jar = httpx.Cookies()
        for name, value in self.auth.cookies.items():
            if self.cookie_domain:
                jar.set(name, value, domain=self.cookie_domain, path="/")
            else:
                jar.set(name, value)
        return jar

    async def __aenter__(self) -> "ScopedHttpClient":
        headers = {"User-Agent": self.config.user_agent}
        # Auth headers (e.g. Authorization) are added as client defaults. httpx
        # strips the Authorization header on cross-origin redirects.
        headers.update(self.auth.headers)
        self._client = httpx.AsyncClient(
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
            follow_redirects=self.config.follow_redirects,
            headers=headers,
            cookies=self._build_cookies(),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        # Scope check is non-negotiable and happens before anything else.
        self.scope.check_url(url)
        if self._client is None:
            raise RuntimeError("client used outside of 'async with' context")

        attempts = self.config.max_retries + 1
        last_exc: Optional[Exception] = None
        for attempt in range(attempts):
            await self._limiter.acquire()
            async with self._sem:
                try:
                    return await self._client.request(method, url, **kwargs)
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_exc = exc
                    if attempt + 1 < attempts:
                        await asyncio.sleep(0.5 * (2**attempt))
                    continue
        assert last_exc is not None
        raise last_exc

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
