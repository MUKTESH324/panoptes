"""Passive check: insecure cookie attributes."""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import List

from ..models import Confidence, Severity
from .base import Plugin, ScanContext, register


@register
class CookieFlags(Plugin):
    name = "cookie-flags"
    description = "Flags cookies missing Secure / HttpOnly / SameSite attributes."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        set_cookies = ctx.response.headers.get_list("set-cookie")
        for raw in set_cookies:
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:  # noqa: BLE001 - malformed cookie, skip
                continue
            for name, morsel in jar.items():
                issues: List[str] = []
                is_https = ctx.url.lower().startswith("https")
                if is_https and not morsel["secure"]:
                    issues.append("missing Secure")
                if not morsel["httponly"]:
                    issues.append("missing HttpOnly")
                if not morsel["samesite"]:
                    issues.append("missing SameSite")
                if not issues:
                    continue
                self._report(
                    ctx,
                    title=f"Cookie '{name}' set with insecure attributes",
                    severity=Severity.LOW,
                    description=(
                        "Cookies without these attributes are more exposed to "
                        "theft (XSS), transport interception and CSRF."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-614",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence=f"Set-Cookie for '{name}': {', '.join(issues)}.",
                    remediation=(
                        "Set cookies with Secure, HttpOnly and an explicit "
                        "SameSite attribute (Lax or Strict) where applicable."
                    ),
                    tags=["cookies", "passive"],
                    site_wide=True,
                )
