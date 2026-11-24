"""Shared test fixtures and fakes (no network access)."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

import httpx
import pytest


def make_response(
    url: str = "https://example.com/",
    status: int = 200,
    headers: Optional[Dict[str, str]] = None,
    text: str = "",
    set_cookies: Optional[List[str]] = None,
) -> httpx.Response:
    hdrs = httpx.Headers(headers or {})
    for cookie in set_cookies or []:
        hdrs = httpx.Headers(list(hdrs.items()) + [("set-cookie", cookie)])
    return httpx.Response(
        status_code=status,
        headers=hdrs,
        content=text.encode("utf-8"),
        request=httpx.Request("GET", url),
    )


class FakeClient:
    """Stand-in for ScopedHttpClient that returns canned responses."""

    def __init__(self, handler: Callable[[str, dict], httpx.Response]):
        self._handler = handler
        self.calls: List[tuple] = []

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self.calls.append((method, url, kwargs))
        return self._handler(url, kwargs)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)


@pytest.fixture
def make_resp():
    return make_response


@pytest.fixture
def fake_client():
    return FakeClient
