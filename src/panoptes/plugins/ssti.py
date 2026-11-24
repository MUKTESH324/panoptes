"""Active check: Server-Side Template Injection (SSTI).

Non-destructive detection: injects a harmless arithmetic expression wrapped in
unique markers across the common template syntaxes. If the server evaluates it,
the response contains the *product* between the markers (e.g. ``pAB1787569ABq``)
— something that cannot appear by reflection alone.
"""

from __future__ import annotations

import secrets

from ..models import Confidence, Severity
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register

# 1337 * 1337 = 1787569 — distinctive enough to avoid false positives.
_FACTOR = "1337*1337"
_PRODUCT = "1787569"
_SYNTAXES = ["{{" + _FACTOR + "}}", "${" + _FACTOR + "}",
             "#{" + _FACTOR + "}", "<%= " + _FACTOR + " %>",
             "{" + _FACTOR + "}"]


@register
class SstiProbe(Plugin):
    name = "ssti"
    description = "Detects server-side template injection via evaluated arithmetic."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        marker = secrets.token_hex(3)
        pre, post = "p" + marker, marker + "q"
        expected = pre + _PRODUCT + post

        for syntax in _SYNTAXES:
            payload = pre + syntax + post
            for param, mutated in iter_param_injections(ctx.url, payload):
                try:
                    resp = await ctx.client.get(mutated)
                except Exception:  # noqa: BLE001
                    continue
                if expected in _safe_text(resp):
                    self._report(
                        ctx,
                        title=f"Server-side template injection in parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            "A template expression injected into this parameter was "
                            "evaluated server-side. SSTI commonly leads to remote "
                            "code execution depending on the template engine."
                        ),
                        confidence=Confidence.FIRM,
                        cwe="CWE-1336",
                        owasp="A03:2021 Injection",
                        evidence=f"Injected {payload!r}; response contained {expected!r} "
                                 f"({_FACTOR} was evaluated to {_PRODUCT}).",
                        remediation=(
                            "Never pass user input into template source. Use a "
                            "sandboxed engine and pass untrusted data only as "
                            "rendering context/variables, never as the template."
                        ),
                        url=mutated,
                        tags=["ssti", "injection", "active"],
                    )
                    return  # one confirmation per URL is enough


def _safe_text(response) -> str:
    try:
        return response.text[:500_000]
    except Exception:  # noqa: BLE001
        return ""
