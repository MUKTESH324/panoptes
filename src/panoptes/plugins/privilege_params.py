"""Passive check: privilege/role parameters exposed to the client.

Flags request parameters and (especially hidden) form fields whose names imply
a privilege or role decision — ``role``, ``is_admin``, ``access_level``,
``account_type``, ``group``, ``permission``, … These are prime candidates for
horizontal/vertical privilege escalation via parameter tampering or mass
assignment (e.g. submitting ``role=admin``). Reported as recon so the tester
can attempt tampering manually.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Severity
from ..utils.forms import parse_forms
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

_PRIV_PARAM = re.compile(
    r"^(?:roles?|is_?admin|admin|is_?staff|staff|is_?superuser|superuser|"
    r"privilege[sd]?|access_?level|user_?type|account_?type|member_?type|"
    r"groups?|permissions?|perms?|level|grant|scopes?|is_?owner|owner|"
    r"can_[a-z_]+|allow_[a-z_]+)$",
    re.IGNORECASE,
)
_MAX = 6


@register
class PrivilegeParams(Plugin):
    name = "privilege-params"
    description = "Flags role/privilege parameters (parameter-tampering / mass-assignment candidates)."
    passive = True

    async def check(self, ctx: ScanContext) -> None:
        if ctx.response is None:
            return
        reported: set = set()

        for name, _value in parse_qsl(urlsplit(ctx.url).query, keep_blank_values=True):
            if _PRIV_PARAM.match(name) and name.lower() not in reported:
                reported.add(name.lower())
                self._emit(ctx, name, "query parameter", "CWE-639")
                if len(reported) >= _MAX:
                    return

        if "html" in ctx.response.headers.get("content-type", "").lower():
            for form in parse_forms(response_text(ctx.response)):
                names = list(form.hidden) + form.text_fields + list(form.all_fields)
                for name in names:
                    if _PRIV_PARAM.match(name) and name.lower() not in reported:
                        reported.add(name.lower())
                        hidden = name in form.hidden
                        self._emit(ctx, name, "hidden form field" if hidden else "form field",
                                   "CWE-915")
                        if len(reported) >= _MAX:
                            return

    def _emit(self, ctx: ScanContext, name: str, where: str, cwe: str) -> None:
        self._report(
            ctx,
            title=f"Privilege-related parameter '{name}' exposed to the client",
            severity=Severity.LOW,
            description=(
                "A parameter that appears to control a role/privilege is exposed "
                "to the client. If the server trusts it, an attacker may escalate "
                "privileges via parameter tampering or mass assignment "
                f"(e.g. setting {name}=admin)."
            ),
            confidence=Confidence.TENTATIVE,
            cwe=cwe,
            owasp="A01:2021 Broken Access Control",
            evidence=f"'{name}' found as a {where}.",
            remediation=(
                "Never derive authorization from client-supplied role/privilege "
                "fields; bind privilege server-side and allowlist assignable fields."
            ),
            tags=["access-control", "parameter-tampering", "authz", "passive"],
        )
