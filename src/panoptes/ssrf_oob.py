"""Out-of-band SSRF confirmation using the bundled listener.

For each URL-like parameter, injects a URL pointing at the OOB listener with a
unique token, triggers the request, waits a grace period, and reports a
**confirmed** blind SSRF for every token the listener actually received — proof
that the server fetched our URL, not just a response-based heuristic.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .models import Confidence, Finding, Severity
from .oob import OobListener
from .plugins.ssrf import _url_like_params


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(new_pairs), parts.fragment))


async def run_ssrf_oob(
    pages: Dict[str, httpx.Response], client, listener: OobListener, grace: float = 3.0,
) -> List[Finding]:
    token_map: Dict[str, Tuple[str, str]] = {}
    for url in list(pages):
        for param in _url_like_params(url):
            token = "px" + secrets.token_hex(6)
            oob_url = f"{listener.base_url}/{token}"
            token_map[token] = (url, param)
            try:
                await client.get(_set_param(url, param, oob_url))
            except Exception:  # noqa: BLE001
                continue

    if not token_map:
        return []
    # Give the target time to perform any asynchronous server-side fetch.
    await asyncio.sleep(grace)

    findings: List[Finding] = []
    for token in listener.tokens_hit():
        if token not in token_map:
            continue
        url, param = token_map.pop(token)  # one finding per confirmed sink
        findings.append(
            Finding(
                plugin="ssrf-oob",
                title=f"Confirmed blind SSRF via parameter '{param}'",
                severity=Severity.HIGH,
                description=(
                    "A URL injected into this parameter was fetched server-side: "
                    "the OOB listener received the unique token. This confirms "
                    "server-side request forgery (not just a heuristic match)."
                ),
                confidence=Confidence.CERTAIN,
                cwe="CWE-918",
                owasp="A10:2021 Server-Side Request Forgery",
                evidence=f"Listener received token {token} injected into '{param}' at {url}.",
                remediation=(
                    "Do not fetch arbitrary user URLs; enforce a scheme/host "
                    "allowlist, resolve and block private/link-local addresses, "
                    "and disable unused URL schemes and redirects."
                ),
                url=url,
                tags=["ssrf", "oob", "confirmed", "active"],
            )
        )
    return findings
