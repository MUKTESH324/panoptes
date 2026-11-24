"""Active check: open redirect via redirect-like parameters."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Severity
from ..utils.inject import iter_param_injections
from .base import Plugin, ScanContext, register

_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_to", "dest", "destination", "continue", "goto", "to",
}
_CANARY = "https://panoptes-redirect-probe.example/"


@register
class OpenRedirect(Plugin):
    name = "open-redirect"
    description = "Detects unvalidated redirects to attacker-controlled hosts."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        params = [n.lower() for n, _ in parse_qsl(urlsplit(ctx.url).query, keep_blank_values=True)]
        if not any(p in _REDIRECT_PARAMS for p in params):
            return

        for param, mutated in iter_param_injections(ctx.url, _CANARY):
            if param.lower() not in _REDIRECT_PARAMS:
                continue
            try:
                # Do NOT follow redirects — we inspect the Location header itself.
                resp = await ctx.client.get(mutated, follow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code not in (301, 302, 303, 307, 308):
                continue
            location = resp.headers.get("location", "")
            if location.startswith(_CANARY) or _host_of(location) == "panoptes-redirect-probe.example":
                self._report(
                    ctx,
                    title=f"Open redirect via parameter '{param}'",
                    severity=Severity.MEDIUM,
                    description=(
                        "The application redirects to a fully attacker-controlled "
                        "URL, usable for phishing and OAuth token theft."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-601",
                    owasp="A01:2021 Broken Access Control",
                    evidence=f"Set Location to external canary: {location}",
                    remediation=(
                        "Redirect only to a server-side allowlist of paths/hosts; "
                        "reject absolute external URLs."
                    ),
                    url=mutated,
                    tags=["open-redirect", "active"],
                )


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
