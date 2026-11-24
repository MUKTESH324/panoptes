"""Active check: reflected XSS (unencoded reflection of a benign marker).

This is a *detection* probe, not an exploit. It injects a unique, harmless
marker wrapped in HTML metacharacters and reports when the metacharacters come
back unencoded in an HTML response — the precondition for reflected XSS.
"""

from __future__ import annotations

import secrets

from ..models import Confidence, Severity
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register


@register
class ReflectedXSS(Plugin):
    name = "reflected-xss"
    description = "Detects unencoded reflection of input in HTML responses."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        marker = secrets.token_hex(6)
        # Benign, self-identifying probe; the angle brackets are the signal.
        payload = f"<panoptes{marker}>"
        for param, mutated in iter_param_injections(ctx.url, payload):
            try:
                resp = await ctx.client.get(mutated)
            except Exception:  # noqa: BLE001
                continue
            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype.lower():
                continue
            body = _safe_text(resp)
            if payload in body:
                self._report(
                    ctx,
                    title=f"Reflected input not HTML-encoded in parameter '{param}'",
                    severity=Severity.HIGH,
                    description=(
                        "User input is reflected into an HTML response without "
                        "encoding, which typically allows reflected XSS."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-79",
                    owasp="A03:2021 Injection",
                    evidence=(
                        f"Injected {payload!r} into '{param}' and it was "
                        "reflected verbatim (angle brackets unencoded)."
                    ),
                    remediation=(
                        "Contextually output-encode all user input; prefer a "
                        "templating engine with auto-escaping and a strict CSP."
                    ),
                    url=mutated,
                    tags=["xss", "injection", "active"],
                )


def _safe_text(response) -> str:
    try:
        return response.text[:500_000]
    except Exception:  # noqa: BLE001
        return ""
