"""Passive check: state-changing HTML forms without an anti-CSRF token.

Heuristic and non-destructive: it parses forms out of the HTML response and
flags any form that uses a state-changing method (POST/PUT/PATCH/DELETE) yet
contains no hidden field whose name looks like a CSRF/synchronizer token.

It is intentionally conservative (reported at FIRM-but-not-certain confidence),
since a site may protect forms with a header token, a SameSite cookie, or a
token injected by JavaScript that static analysis can't see.
"""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from .base import Plugin, ScanContext, register

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?\s*(post|put|patch|delete)""", re.IGNORECASE)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_TOKEN_NAME_RE = re.compile(
    r"csrf|xsrf|_token|authenticity_token|requestverification|anti-?csrf|nonce|"
    r"__requestverificationtoken",
    re.IGNORECASE,
)
_MAX_PER_PAGE = 5


@register
class CsrfForms(Plugin):
    name = "csrf"
    description = "Flags state-changing HTML forms with no apparent anti-CSRF token."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        if "html" not in ctx.response.headers.get("content-type", "").lower():
            return
        body = _safe_text(ctx.response)
        reported = 0
        for attrs, inner in _FORM_RE.findall(body):
            if reported >= _MAX_PER_PAGE:
                break
            if not _METHOD_RE.search(attrs):
                continue  # not a state-changing form (GET / unspecified)
            names = _INPUT_NAME_RE.findall(attrs + inner)
            if any(_TOKEN_NAME_RE.search(n) for n in names):
                continue  # looks like it has a CSRF token field
            action_m = _ACTION_RE.search(attrs)
            action = action_m.group(1) if action_m else "(self)"
            self._report(
                ctx,
                title="State-changing form without an anti-CSRF token",
                severity=Severity.MEDIUM,
                description=(
                    "A POST/PUT/PATCH/DELETE form was found with no hidden "
                    "anti-CSRF token field. If the session relies only on "
                    "cookies (without SameSite), it may be forgeable cross-site."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-352",
                owasp="A01:2021 Broken Access Control",
                evidence=f"Form action={action!r} with no token-like hidden input.",
                remediation=(
                    "Add a per-session synchronizer token (or double-submit "
                    "cookie) and verify it server-side; set session cookies "
                    "SameSite=Lax or Strict."
                ),
                tags=["csrf", "passive"],
            )
            reported += 1


def _safe_text(response) -> str:
    try:
        return response.text[:500_000]
    except Exception:  # noqa: BLE001
        return ""
