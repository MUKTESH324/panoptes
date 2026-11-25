"""Browser-driven XSS confirmation (Playwright).

The httpx-based reflected/stored/DOM checks prove *reflection*; this proves
*execution*. It injects a payload that, if it runs, sets a unique global
(``window.__panoptes_xss = 1``), loads the page in headless Chromium, and
reports a CERTAIN finding only when that global is set — i.e. script actually
executed in the real DOM.

Playwright is optional (the ``browser`` extra). Without it, verification is
skipped and the heuristic findings stand.
"""

from __future__ import annotations

import importlib.util
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from .models import Confidence, Finding, Severity
from .utils.forms import parse_forms
from .utils.http import response_text
from .utils.inject import has_query_params, iter_param_injections

# Payload sets a unique global iff it executes (img onerror runs even without a script-src).
_EXEC_PAYLOAD = '"><img src=x onerror="window.__panoptes_xss=1">'
_CHECK_JS = "() => window.__panoptes_xss === 1"


class XssVerifier:
    def __init__(self, scope, timeout: float = 15.0,
                 cookies: Optional[Dict[str, str]] = None) -> None:
        self.scope = scope
        self.timeout = timeout
        self.cookies = cookies or {}

    @staticmethod
    def available() -> bool:
        return importlib.util.find_spec("playwright") is not None

    async def executes(self, url: str) -> bool:
        """Load url in headless Chromium; return True if the payload executed."""
        try:
            from playwright.async_api import async_playwright
        except Exception:  # noqa: BLE001
            return False
        try:
            self.scope.check_url(url)
        except Exception:  # noqa: BLE001
            return False
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                context.on("dialog", lambda d: d.dismiss())  # don't hang on alert()
                if self.cookies:
                    host = urlsplit(url).hostname or ""
                    await context.add_cookies(
                        [{"name": k, "value": v, "domain": host, "path": "/"}
                         for k, v in self.cookies.items()]
                    )
                page = await context.new_page()
                fired = False
                try:
                    await page.goto(url, wait_until="networkidle",
                                    timeout=int(self.timeout * 1000))
                    fired = bool(await page.evaluate(_CHECK_JS))
                except Exception:  # noqa: BLE001
                    fired = False
                await browser.close()
                return fired
        except Exception:  # noqa: BLE001
            return False


async def verify_reflected(urls: List[str], verifier) -> List[Finding]:
    findings: List[Finding] = []
    for url in urls:
        if not has_query_params(url):
            continue
        for param, mutated in iter_param_injections(url, _EXEC_PAYLOAD):
            if await verifier.executes(mutated):
                findings.append(_finding(
                    "Browser-confirmed reflected XSS in parameter '%s'" % param,
                    f"An injected payload executed in the browser via '{param}'.",
                    mutated, ["xss", "reflected", "browser-verified"]))
                break  # one confirmation per URL
    return findings


async def verify_stored(pages: Dict[str, httpx.Response], verifier, client) -> List[Finding]:
    submitted = False
    for url, resp in pages.items():
        if "html" not in resp.headers.get("content-type", "").lower():
            continue
        for form in parse_forms(response_text(resp)):
            if not form.text_fields:
                continue
            data = dict(form.hidden)
            for fld in form.text_fields:
                data[fld] = _EXEC_PAYLOAD
            action = urljoin(url, form.action or url)
            try:
                if form.method == "post":
                    await client.post(action, data=data)
                else:
                    await client.get(action, params=data)
                submitted = True
            except Exception:  # noqa: BLE001
                continue
    if not submitted:
        return []
    findings: List[Finding] = []
    seen = set()
    for url in list(pages):
        if url in seen:
            continue
        if await verifier.executes(url):
            seen.add(url)
            findings.append(_finding(
                "Browser-confirmed stored XSS",
                "A submitted payload executed in the browser on this page.",
                url, ["xss", "stored", "browser-verified"]))
    return findings


def _finding(title: str, desc: str, url: str, tags: List[str]) -> Finding:
    return Finding(
        plugin="xss-verified",
        title=title,
        severity=Severity.HIGH,
        description=desc + " This is a confirmed execution, not a reflection heuristic.",
        confidence=Confidence.CERTAIN,
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        evidence="window.__panoptes_xss was set after loading the payload in headless Chromium.",
        remediation="Contextually output-encode user input and enforce a strict CSP.",
        url=url,
        tags=tags + ["active"],
    )
