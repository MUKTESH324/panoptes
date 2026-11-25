"""Passive check: information disclosure (version banners, stack traces)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

_VERSION_RE = re.compile(r"\d+\.\d+")
_STACK_SIGNS = (
    "Traceback (most recent call last)",
    "java.lang.",
    "System.NullReferenceException",
    "org.springframework",
    "Warning: ",  # PHP
    "Fatal error:",
    "ORA-0",
    "SQLSTATE[",
)


@register
class InfoDisclosure(Plugin):
    name = "info-disclosure"
    description = "Detects version banners and leaked stack traces/errors."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        headers = {k.lower(): v for k, v in ctx.response.headers.items()}

        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = headers.get(header, "")
            if value and _VERSION_RE.search(value):
                self._report(
                    ctx,
                    title=f"Software version disclosed in '{header}' header",
                    severity=Severity.INFO,
                    description=(
                        "Precise version banners help attackers match known "
                        "CVEs to the stack."
                    ),
                    confidence=Confidence.CERTAIN,
                    cwe="CWE-200",
                    evidence=f"{header}: {value}",
                    remediation="Suppress or genericize version banners.",
                    tags=["disclosure", "passive"],
                    site_wide=True,
                )

        body = response_text(ctx.response)
        for sign in _STACK_SIGNS:
            if sign in body:
                self._report(
                    ctx,
                    title="Verbose error / stack trace disclosed in response",
                    severity=Severity.LOW,
                    description=(
                        "Stack traces and raw error messages reveal internal "
                        "paths, libraries and logic useful to an attacker."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-209",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence=f"Response body contains error signature: {sign!r}",
                    remediation=(
                        "Return generic error pages; log details server-side only."
                    ),
                    tags=["disclosure", "passive"],
                )
                break

