"""Active check: HTTP method / verb-tampering access-control bypass.

When an endpoint is *denied* to the current identity (401/403/405), this tries
the same URL with alternate methods and method-override headers
(``X-HTTP-Method-Override`` etc.). If any of those returns a successful,
non-empty response, access control is enforced only for some verbs and can be
bypassed — a common horizontal/vertical privilege-escalation primitive.

It only acts on already-denied endpoints, so it never escalates an endpoint the
caller could already reach.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

# (method, extra headers) combinations to try against a denied endpoint.
_ATTEMPTS: List[Tuple[str, Dict[str, str]]] = [
    ("POST", {}),
    ("PUT", {}),
    ("PATCH", {}),
    ("GET", {"X-HTTP-Method-Override": "GET"}),
    ("GET", {"X-HTTP-Method": "GET"}),
    ("GET", {"X-Original-Method": "GET"}),
    ("POST", {"X-HTTP-Method-Override": "GET"}),
]
_DENIED = {401, 403, 405}


@register
class MethodTampering(Plugin):
    name = "method-tampering"
    description = "Detects access control bypass via HTTP method / override-header tampering."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None or ctx.response.status_code not in _DENIED:
            return
        denied_status = ctx.response.status_code

        for method, headers in _ATTEMPTS:
            try:
                resp = await ctx.client.request(method, ctx.url, headers=headers)
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code == 200 and response_text(resp).strip():
                how = f"{method}" + (f" with {', '.join(headers)}" if headers else "")
                self._report(
                    ctx,
                    title="Access control bypass via HTTP method tampering",
                    severity=Severity.HIGH,
                    description=(
                        "The endpoint denies the normal request but grants access "
                        "to a tampered method/override, so authorization is "
                        "enforced per-verb and can be bypassed."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-650",
                    owasp="A01:2021 Broken Access Control",
                    evidence=(
                        f"GET returned {denied_status}, but {how} returned 200 "
                        "with a body."
                    ),
                    remediation=(
                        "Apply authorization checks uniformly across all HTTP "
                        "methods; ignore method-override headers unless explicitly "
                        "needed and still authorize the effective action."
                    ),
                    tags=["access-control", "method-tampering", "authz", "active"],
                )
                return
