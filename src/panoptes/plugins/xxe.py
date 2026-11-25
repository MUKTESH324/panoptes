"""Active check: XML External Entity (XXE) injection.

In-band detection only. Posts an XML document that declares an external entity
pointing at a world-readable system file (``/etc/passwd``) and looks for that
file's signature in the response. It reads a standard file to prove the parser
resolves external entities; it does not exfiltrate data out-of-band, hit
internal URLs, or target sensitive paths.

It probes each host's first page once, plus any URL whose response is XML.
"""

from __future__ import annotations

import re
from typing import Set

from ..models import Confidence, Severity
from ..utils.http import response_text
from ..utils.urls import origin
from .base import Plugin, ScanContext, register

_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE panoptes [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    "<panoptes>&xxe;</panoptes>"
)
_SIGNATURE = re.compile(r"root:.*?:0:0:")


@register
class Xxe(Plugin):
    name = "xxe"
    description = "Detects XML external entity (XXE) processing via in-band file read."
    passive = False

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    async def check(self, ctx: ScanContext) -> None:
        candidates = set()
        if ctx.response is not None and "xml" in ctx.response.headers.get("content-type", "").lower():
            candidates.add(ctx.url)
        host = origin(ctx.url)
        if host not in self._seen:
            self._seen.add(host)
            candidates.add(ctx.url)

        for url in candidates:
            try:
                resp = await ctx.client.post(
                    url, content=_XXE_PAYLOAD,
                    headers={"Content-Type": "application/xml"},
                )
            except Exception:  # noqa: BLE001
                continue
            if _SIGNATURE.search(response_text(resp)):
                self._report(
                    ctx,
                    title="XML External Entity (XXE) processing",
                    severity=Severity.HIGH,
                    description=(
                        "The endpoint parsed an XML document and resolved an "
                        "external entity, returning the contents of a local file. "
                        "XXE enables local file disclosure and can be chained to "
                        "SSRF and denial of service."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-611",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence=f"XXE payload to {url} returned /etc/passwd content.",
                    remediation=(
                        "Disable external entity and DTD processing in the XML "
                        "parser (e.g. FEATURE_SECURE_PROCESSING, disallow-doctype-decl)."
                    ),
                    url=url,
                    tags=["xxe", "injection", "active"],
                )
                return
