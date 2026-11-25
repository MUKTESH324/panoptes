"""Active check: Server-Side Request Forgery (SSRF) sinks.

Detection, not exploitation. For each parameter that looks like it takes a URL,
the probe substitutes a **non-resolvable** canary host under the reserved
``.invalid`` TLD (RFC 6761 — it never resolves, so nothing internal is actually
contacted) and then looks for evidence that the *server* tried to fetch it:

  * a fetch / DNS-resolution error that mentions our unique canary host, or
  * a server-side fetch error that the baseline response did not have.

Either is a strong indicator that user input reaches a server-side HTTP client
(the SSRF precondition). The probe deliberately does **not** target cloud
metadata endpoints or internal IP ranges — confirming and exploiting a sink is
a manual, authorized follow-up.

Optional out-of-band mode: set ``PANOPTES_SSRF_CANARY`` to a listener you
control (e.g. an interactsh/collaborator domain) and the probe will also send a
tokenised URL to it and emit an informational finding so you can check your
listener for blind SSRF.
"""

from __future__ import annotations

import os
import re
import secrets
from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Severity
from ..utils.http import response_text
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register

# Parameter names that commonly carry a URL / host the server may fetch.
_URL_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirecturl", "redirect_url", "next", "continue", "forward",
    "return", "returnurl", "return_url", "rurl", "callback", "webhook", "fetch",
    "load", "remote", "proxy", "feed", "image", "imageurl", "image_url", "img",
    "host", "domain", "site", "target", "open", "document", "resource", "path_url",
}

_FETCH_ERROR_RE = re.compile(
    r"could\s*not\s*resolve\s*host|getaddrinfo|name or service not known|"
    r"nodename nor servname|temporary failure in name resolution|"
    r"failed to resolve|no address associated with hostname|name resolution|"
    r"connection refused|econnrefused|connection timed out|etimedout|"
    r"failed to connect|couldn'?t connect to host|unable to connect|"
    r"curl error|cURL error|failed to open stream|urlopen error|"
    r"invalid_url|no route to host",
    re.IGNORECASE,
)


@register
class SsrfProbe(Plugin):
    name = "ssrf"
    description = "Detects server-side request forgery sinks (server fetches a supplied URL)."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        targets = _url_like_params(ctx.url)
        if not targets:
            return

        baseline = response_text(ctx.response) if ctx.response is not None else ""
        baseline_error = bool(_FETCH_ERROR_RE.search(baseline))

        token = secrets.token_hex(5)
        probe_host = f"panoptes-ssrf-{token}.invalid"
        probe_url = f"http://{probe_host}/"

        for param, mutated in iter_param_injections(ctx.url, probe_url):
            if param not in targets:
                continue
            try:
                resp = await ctx.client.get(mutated)
            except Exception:  # noqa: BLE001
                continue
            body = response_text(resp)
            host_echoed_in_error = probe_host in body and bool(_FETCH_ERROR_RE.search(body))
            new_fetch_error = bool(_FETCH_ERROR_RE.search(body)) and not baseline_error

            if host_echoed_in_error:
                confidence = Confidence.FIRM
                evidence = (
                    f"Injected {probe_url!r} into '{param}'; server returned a "
                    f"fetch error naming the canary host {probe_host}."
                )
            elif new_fetch_error:
                confidence = Confidence.TENTATIVE
                evidence = (
                    f"Injected {probe_url!r} into '{param}'; a server-side fetch "
                    "error appeared that the baseline response did not have."
                )
            else:
                continue

            self._report(
                ctx,
                title=f"Possible SSRF via parameter '{param}'",
                severity=Severity.HIGH,
                description=(
                    "User-supplied input in this parameter appears to be fetched "
                    "server-side. SSRF can be used to reach internal services, "
                    "cloud metadata endpoints, and otherwise-unreachable hosts."
                ),
                confidence=confidence,
                cwe="CWE-918",
                owasp="A10:2021 Server-Side Request Forgery",
                evidence=evidence,
                remediation=(
                    "Do not fetch arbitrary user URLs. Enforce an allowlist of "
                    "schemes/hosts, resolve and validate the address (block "
                    "private/link-local ranges), and disable unused URL schemes "
                    "and redirects on the server-side client."
                ),
                url=mutated,
                tags=["ssrf", "injection", "active"],
            )

        await self._oob_probe(ctx, targets, token)

    async def _oob_probe(self, ctx: ScanContext, targets: set, token: str) -> None:
        """Optional out-of-band probe when a listener is configured."""
        canary = os.getenv("PANOPTES_SSRF_CANARY", "").strip().rstrip("/")
        if not canary:
            return
        if "://" not in canary:
            canary = "http://" + canary
        oob_url = f"{canary}/{token}"
        sent = []
        for param, mutated in iter_param_injections(ctx.url, oob_url):
            if param not in targets:
                continue
            try:
                await ctx.client.get(mutated)
                sent.append(param)
            except Exception:  # noqa: BLE001
                continue
        if sent:
            self._report(
                ctx,
                title="Blind SSRF out-of-band probe sent — verify your listener",
                severity=Severity.INFO,
                description=(
                    "An out-of-band SSRF payload was delivered. Check your "
                    "collaborator/interactsh listener for an interaction with "
                    "the token below; a hit confirms blind SSRF."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-918",
                owasp="A10:2021 Server-Side Request Forgery",
                evidence=f"Sent {canary}/{token} via parameter(s): {', '.join(sent)}",
                remediation="If your listener was hit, treat as SSRF and remediate as above.",
                tags=["ssrf", "oob", "active"],
            )


def _url_like_params(url: str) -> set:
    out = set()
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name.lower() in _URL_PARAM_NAMES:
            out.add(name)
        elif value.lower().startswith(("http://", "https://")) or value.startswith("//"):
            out.add(name)
    return out

