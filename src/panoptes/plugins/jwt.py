"""Passive check: JSON Web Token weaknesses.

Finds JWTs the application exposes to the client (in Set-Cookie, response
headers, the body, or the URL) and inspects their *structure* only — it decodes
the header and payload (which are just base64url, readable by anyone holding the
token) and never attempts to forge, tamper with, or brute-force a signature.

Flags:
  * ``alg: none``                     -> HIGH  (unsigned token accepted)
  * JWT carried in the URL/query      -> MEDIUM (leaks via logs, referrer, history)
  * no ``exp`` claim                  -> LOW    (token never expires)
  * sensitive-looking claims in body  -> LOW    (information disclosure)
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Dict, Optional

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

# header.payload.signature — signature may be empty (alg=none).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_SENSITIVE_CLAIMS = re.compile(
    r"password|passwd|pwd|secret|ssn|credit|card|api[_-]?key|private", re.IGNORECASE
)


@register
class JwtChecks(Plugin):
    name = "jwt"
    description = "Detects JWT weaknesses (alg:none, no expiry, token in URL, claim leakage)."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        tokens_in_url = set(_JWT_RE.findall(ctx.url))
        tokens = set(tokens_in_url)
        if ctx.response is not None:
            for _k, value in ctx.response.headers.items():
                tokens.update(_JWT_RE.findall(value))
            tokens.update(_JWT_RE.findall(response_text(ctx.response)))

        for token in tokens:
            self._analyze(ctx, token, in_url=token in tokens_in_url)

    def _analyze(self, ctx: ScanContext, token: str, in_url: bool) -> None:
        header = _decode_segment(token.split(".")[0])
        payload = _decode_segment(token.split(".")[1]) if token.count(".") >= 1 else None
        if header is None or payload is None:
            return  # not a decodable JWT
        snippet = token[:12] + "…"

        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            self._report(
                ctx,
                title="JWT accepted with 'none' algorithm (unsigned)",
                severity=Severity.HIGH,
                description=(
                    "A JWT uses the 'none' algorithm, meaning it carries no "
                    "signature. If the server accepts it, tokens can be forged "
                    "arbitrarily."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-347",
                owasp="A02:2021 Cryptographic Failures",
                evidence=f"JWT header alg={header.get('alg')!r} (token {snippet})",
                remediation="Reject 'none'; require a strong signature (e.g. RS256) and verify it.",
                tags=["jwt", "passive"],
            )

        if in_url:
            self._report(
                ctx,
                title="JWT transmitted in the URL",
                severity=Severity.MEDIUM,
                description=(
                    "A JWT appears in the request URL, so it leaks into server "
                    "logs, browser history, and the Referer header."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-598",
                evidence=f"JWT in URL ({snippet})",
                remediation="Send tokens in a header or a Secure/HttpOnly cookie, not the URL.",
                tags=["jwt", "passive"],
            )

        if "exp" not in payload:
            self._report(
                ctx,
                title="JWT has no expiration (exp) claim",
                severity=Severity.LOW,
                description=(
                    "The token has no 'exp' claim, so it does not expire — a "
                    "leaked token remains valid indefinitely."
                ),
                confidence=Confidence.FIRM,
                cwe="CWE-613",
                evidence=f"payload claims: {sorted(payload)} (token {snippet})",
                remediation="Issue short-lived tokens with an 'exp' claim and honor it.",
                tags=["jwt", "passive"],
            )

        leaked = [k for k in payload if _SENSITIVE_CLAIMS.search(str(k))]
        if leaked:
            self._report(
                ctx,
                title="JWT payload contains sensitive-looking claims",
                severity=Severity.LOW,
                description=(
                    "The JWT payload is only base64-encoded (not encrypted) and "
                    "appears to carry sensitive data, readable by anyone holding "
                    "the token."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-200",
                evidence=f"claims resembling secrets: {leaked} (token {snippet})",
                remediation="Keep secrets out of JWT payloads; store only non-sensitive identifiers.",
                tags=["jwt", "passive"],
            )


def _decode_segment(seg: str) -> Optional[Dict[str, Any]]:
    try:
        pad = "=" * (-len(seg) % 4)
        raw = base64.urlsafe_b64decode(seg + pad)
        data = json.loads(raw)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None

