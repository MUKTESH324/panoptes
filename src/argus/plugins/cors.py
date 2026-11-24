"""Active check: permissive / reflected CORS policy."""

from __future__ import annotations

from ..models import Confidence, Severity
from .base import Plugin, ScanContext, register

_PROBE_ORIGIN = "https://argus-cors-probe.example"


@register
class CorsMisconfig(Plugin):
    name = "cors-misconfig"
    description = "Detects origin-reflecting or wildcard-with-credentials CORS."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        try:
            resp = await ctx.client.get(ctx.url, headers={"Origin": _PROBE_ORIGIN})
        except Exception:  # noqa: BLE001
            return
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if not acao:
            return

        if acao == _PROBE_ORIGIN:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            self._report(
                ctx,
                title="CORS policy reflects arbitrary Origin",
                severity=sev,
                description=(
                    "The server echoes an attacker-supplied Origin in "
                    "Access-Control-Allow-Origin"
                    + (" with credentials allowed" if acac == "true" else "")
                    + ", letting malicious sites read authenticated responses."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
                evidence=(
                    f"Sent Origin: {_PROBE_ORIGIN} -> "
                    f"Access-Control-Allow-Origin: {acao}, "
                    f"Allow-Credentials: {acac or 'absent'}"
                ),
                remediation=(
                    "Validate Origin against a strict allowlist; never reflect "
                    "it. Only enable Allow-Credentials for trusted origins."
                ),
                tags=["cors", "active"],
            )
        elif acao == "*" and acac == "true":
            self._report(
                ctx,
                title="CORS wildcard combined with credentials",
                severity=Severity.MEDIUM,
                description=(
                    "Access-Control-Allow-Origin: * together with "
                    "Allow-Credentials: true is an invalid but dangerous "
                    "configuration some clients honor."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-942",
                evidence="ACAO: * with Allow-Credentials: true",
                remediation="Do not combine wildcard origins with credentials.",
                tags=["cors", "active"],
            )
