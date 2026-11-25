"""Stored (persistent) XSS detection.

Server-rendered stored XSS: submit a unique marker containing HTML
metacharacters through each form's text fields, then re-fetch the crawled pages
and report any page where the marker comes back **unencoded** — meaning the
payload was stored and rendered without escaping.

This writes benign test data (a ``<panostored-xxxx>`` marker) to the target, so
it is **opt-in** (``--stored-xss`` / ``stored_xss: true``). Use it only where you
are authorized to create data, ideally with a test account.
"""

from __future__ import annotations

import secrets
from typing import Dict, List
from urllib.parse import urljoin

import httpx

from .models import Confidence, Finding, Severity
from .utils.forms import parse_forms
from .utils.http import response_text


async def find_stored_xss(pages: Dict[str, httpx.Response], client) -> List[Finding]:
    marker = "panostored" + secrets.token_hex(4)
    payload = "<" + marker + ">"  # the angle brackets are the signal
    submitted_any = False

    for url, resp in pages.items():
        if "html" not in resp.headers.get("content-type", "").lower():
            continue
        for form in parse_forms(response_text(resp)):
            if not form.text_fields:
                continue
            data = dict(form.hidden)
            for fld in form.text_fields:
                data[fld] = payload
            action = urljoin(url, form.action or url)
            try:
                if form.method == "post":
                    await client.post(action, data=data)
                else:
                    await client.get(action, params=data)
                submitted_any = True
            except Exception:  # noqa: BLE001 (out-of-scope / network)
                continue

    if not submitted_any:
        return []

    findings: List[Finding] = []
    seen: set = set()
    for url in list(pages):
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if "html" not in resp.headers.get("content-type", "").lower():
            continue
        if payload in response_text(resp) and url not in seen:
            seen.add(url)
            findings.append(
                Finding(
                    plugin="stored-xss",
                    title="Stored XSS — submitted markup persisted unencoded",
                    severity=Severity.HIGH,
                    description=(
                        "A marker containing HTML metacharacters was submitted via "
                        "a form and later returned unencoded on this page, "
                        "indicating stored (persistent) cross-site scripting."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-79",
                    owasp="A03:2021 Injection",
                    evidence=f"Marker {payload!r} persisted and was reflected unencoded at {url}.",
                    remediation=(
                        "Contextually output-encode stored data on render and "
                        "validate input on write; apply a strict CSP."
                    ),
                    url=url,
                    tags=["stored-xss", "xss", "active"],
                )
            )
    return findings

