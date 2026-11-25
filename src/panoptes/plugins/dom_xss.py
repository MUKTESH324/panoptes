"""Passive check: DOM-based XSS (static source -> sink analysis).

Inspects client-side JavaScript (inline <script> blocks, inline event handlers,
and ``javascript:`` URIs) for a user-controllable **source** (``location.hash``,
``location.search``, ``document.referrer``, ``window.name``, ``postMessage``
data, …) co-occurring with a dangerous **sink** (``innerHTML``,
``document.write``, ``eval``, ``setTimeout`` with a string, jQuery ``.html()``,
…). When both appear, the page may be vulnerable to DOM XSS.

This is a heuristic (reported at tentative confidence / "needs review"): it does
not perform data-flow analysis, so it flags candidates for manual confirmation
rather than proven bugs. It needs no browser.
"""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_EVENT_ATTR_RE = re.compile(r"""\bon\w+\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_JS_URI_RE = re.compile(r"""(?:href|src)\s*=\s*(?:"javascript:([^"]*)"|'javascript:([^']*)')""", re.IGNORECASE)

_SOURCE_RE = re.compile(
    r"location\.(?:hash|search|href|pathname|host)\b|"
    r"document\.(?:URL|documentURI|baseURI|referrer|cookie)\b|"
    r"window\.name\b|URLSearchParams\b|\.getParameter\s*\(|"
    r"\bevent\.data\b|\bpostMessage\b",
    re.IGNORECASE,
)
_SINK_RE = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|"
    r"document\.write(?:ln)?\s*\(|\beval\s*\(|\bFunction\s*\(|"
    r"setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]|"
    r"\.html\s*\(|jQuery\.globalEval|\$\([^)]*\)\.html\s*\(",
    re.IGNORECASE,
)


@register
class DomXss(Plugin):
    name = "dom-xss"
    description = "Detects likely DOM-based XSS (user-controlled source into a JS sink)."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        if "html" not in ctx.response.headers.get("content-type", "").lower():
            return
        js = _extract_js(response_text(ctx.response, limit=800_000))
        if not js:
            return
        source = _SOURCE_RE.search(js)
        sink = _SINK_RE.search(js)
        if source and sink:
            self._report(
                ctx,
                title="Potential DOM-based XSS (tainted source reaches a JS sink)",
                severity=Severity.MEDIUM,
                description=(
                    "Client-side JavaScript reads a user-controllable source and "
                    "also uses a dangerous sink. If the source flows to the sink "
                    "without sanitization, the page is vulnerable to DOM XSS."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-79",
                owasp="A03:2021 Injection",
                evidence=f"source {source.group(0)!r} and sink {sink.group(0)!r} present in page scripts.",
                remediation=(
                    "Treat URL/DOM data as untrusted; use safe DOM APIs "
                    "(textContent, setAttribute), sanitize with a vetted library "
                    "(e.g. DOMPurify) before innerHTML, and avoid eval/"
                    "document.write."
                ),
                tags=["dom-xss", "xss", "passive"],
            )


def _extract_js(html: str) -> str:
    parts = []
    parts.extend(_SCRIPT_RE.findall(html))
    for a, b in _EVENT_ATTR_RE.findall(html):
        parts.append(a or b)
    for a, b in _JS_URI_RE.findall(html):
        parts.append(a or b)
    return "\n".join(parts)

