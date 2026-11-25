"""Passive check: insecure-deserialization indicators.

Looks for serialized object blobs the application hands to the client — in
cookies, URL parameters, and the response body. These are *indicators*: a
serialized blob round-tripped through the client is the precondition for an
insecure-deserialization bug, but confirming exploitability is manual. Reported
at tentative confidence.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

# (signature, label) — matched against cookie/param values and (some) body text.
_SIGNATURES = [
    (re.compile(r"rO0AB"), "Java serialized object (base64 'rO0AB…')"),
    (re.compile(r"aced0005", re.IGNORECASE), "Java serialized object (hex 'aced0005')"),
    (re.compile(r"O:\d+:\"[^\"]+\":\d+:\{"), "PHP serialized object"),
    (re.compile(r"__VIEWSTATE"), ".NET ViewState"),
]
# Pickle markers are FP-prone, so only trust them in cookie/param values.
_PICKLE = re.compile(r"\bgASV|\bgAJ")


@register
class Deserialization(Plugin):
    name = "deserialization"
    description = "Flags serialized object blobs (insecure-deserialization indicators)."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        values = []
        if ctx.response is not None:
            for raw in ctx.response.headers.get_list("set-cookie"):
                values.append(("cookie", raw))
        for name, value in parse_qsl(urlsplit(ctx.url).query, keep_blank_values=True):
            values.append((f"parameter '{name}'", value))

        reported = set()
        for where, value in values:
            for sig, label in _SIGNATURES + [(_PICKLE, "Python pickle (base64)")]:
                if sig.search(value) and label not in reported:
                    reported.add(label)
                    self._emit(ctx, label, where)

        # In the body, only trust the lower-FP signatures.
        if ctx.response is not None:
            body = response_text(ctx.response)
            for sig, label in _SIGNATURES[:1] + _SIGNATURES[2:]:
                if sig.search(body) and label not in reported:
                    reported.add(label)
                    self._emit(ctx, label, "response body")

    def _emit(self, ctx: ScanContext, label: str, where: str) -> None:
        self._report(
            ctx,
            title="Serialized object exposed to the client",
            severity=Severity.LOW,
            description=(
                "A serialized object blob is round-tripped through the client. "
                "If the server deserializes it without integrity checks, it may "
                "be vulnerable to insecure deserialization (potential RCE)."
            ),
            confidence=Confidence.TENTATIVE,
            cwe="CWE-502",
            owasp="A08:2021 Software and Data Integrity Failures",
            evidence=f"{label} found in {where}.",
            remediation=(
                "Avoid native deserialization of client data; sign/encrypt such "
                "blobs, or use a safe data format (JSON) with strict schemas."
            ),
            tags=["deserialization", "passive"],
        )
