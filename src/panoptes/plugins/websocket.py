"""Passive check: WebSocket usage and cleartext WebSocket endpoints.

Scans page JavaScript/HTML for WebSocket endpoints. Flags cleartext ``ws://``
(no transport encryption) and otherwise notes that WebSockets are in use so the
tester can review origin validation and authentication on the channel — things
static analysis can't confirm on its own.
"""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

_WS_URL_RE = re.compile(r"(wss?://[^\s\"'<>()]+)", re.IGNORECASE)
_WS_API_RE = re.compile(r"new\s+WebSocket\s*\(|io\.connect\s*\(|io\s*\(|socket\.io", re.IGNORECASE)


@register
class WebSocketCheck(Plugin):
    name = "websocket"
    description = "Detects WebSocket endpoints and flags cleartext ws:// usage."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        if "html" not in ctx.response.headers.get("content-type", "").lower():
            return
        body = response_text(ctx.response)
        urls = _WS_URL_RE.findall(body)
        has_api = bool(_WS_API_RE.search(body))
        if not urls and not has_api:
            return

        cleartext = [u for u in urls if u.lower().startswith("ws://")]
        if cleartext:
            self._report(
                ctx,
                title="Cleartext WebSocket endpoint (ws://)",
                severity=Severity.LOW,
                description=(
                    "A ws:// WebSocket endpoint is used, so WebSocket traffic is "
                    "unencrypted and open to interception and tampering."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                evidence=f"Cleartext endpoint(s): {', '.join(sorted(set(cleartext))[:3])}",
                remediation="Use wss:// (TLS) for all WebSocket connections.",
                tags=["websocket", "passive"],
            )
        else:
            self._report(
                ctx,
                title="WebSocket endpoint in use",
                severity=Severity.INFO,
                description=(
                    "The page opens WebSocket connections. Review that the server "
                    "validates the Origin header and authenticates/authorizes the "
                    "WebSocket handshake and messages."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-1385",
                evidence=(f"endpoint(s): {', '.join(sorted(set(urls))[:3])}" if urls
                          else "WebSocket client API used in page scripts."),
                remediation="Validate Origin and enforce auth on the WebSocket handshake.",
                tags=["websocket", "passive"],
            )
