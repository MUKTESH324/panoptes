"""Passive check: missing or weak HTTP security headers."""

from __future__ import annotations

from ..models import Confidence, Severity
from .base import Plugin, ScanContext, register

_CHECKS = [
    (
        "content-security-policy",
        Severity.MEDIUM,
        "Content-Security-Policy header is missing",
        "A CSP mitigates XSS and data-injection by restricting the sources from "
        "which content may load.",
        "Define a restrictive Content-Security-Policy, starting from "
        "`default-src 'self'` and tightening per resource type.",
        "CWE-693",
    ),
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "HTTP Strict Transport Security (HSTS) header is missing",
        "Without HSTS, clients may be downgraded to plaintext HTTP and are "
        "exposed to SSL-stripping attacks.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "on HTTPS responses.",
        "CWE-319",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "X-Content-Type-Options header is missing",
        "Browsers may MIME-sniff responses, enabling content-type confusion.",
        "Send `X-Content-Type-Options: nosniff`.",
        "CWE-693",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "Clickjacking protection (X-Frame-Options / frame-ancestors) is missing",
        "The page can be framed by other origins, enabling clickjacking.",
        "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'self'`.",
        "CWE-1021",
    ),
    (
        "referrer-policy",
        Severity.INFO,
        "Referrer-Policy header is missing",
        "A permissive referrer policy can leak sensitive URLs to third parties.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
        "CWE-200",
    ),
]


@register
class SecurityHeaders(Plugin):
    name = "security-headers"
    description = "Detects missing or weak HTTP security headers."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        headers = {k.lower(): v for k, v in ctx.response.headers.items()}
        has_csp = "content-security-policy" in headers
        for header, severity, title, desc, fix, cwe in _CHECKS:
            # frame-ancestors in CSP satisfies clickjacking protection.
            if header == "x-frame-options" and has_csp and "frame-ancestors" in headers.get(
                "content-security-policy", ""
            ):
                continue
            if header not in headers:
                self._report(
                    ctx,
                    title=title,
                    severity=severity,
                    description=desc,
                    confidence=Confidence.CERTAIN,
                    cwe=cwe,
                    owasp="A05:2021 Security Misconfiguration",
                    evidence=f"Response for {ctx.url} did not include '{header}'.",
                    remediation=fix,
                    tags=["headers", "passive"],
                    site_wide=True,
                )
