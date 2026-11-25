"""Active check: error-based SQL injection indicators.

Appends a single quote to each parameter and looks for database error
signatures in the response. This only *detects* a likely injection point; it
never attempts data extraction or any destructive query.
"""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..utils.http import response_text
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register

_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"psql:\s+error",
    r"sqlite3?::",
    r"sqlite_error",
    r"ora-\d{5}",
    r"odbc\s+driver",
    r"microsoft ole db provider for sql server",
]
_SQL_RE = re.compile("|".join(_SQL_ERRORS), re.IGNORECASE)


@register
class SqliError(Plugin):
    name = "sqli-error"
    description = "Detects error-based SQL injection via database error signatures."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        baseline = response_text(ctx.response) if ctx.response is not None else ""
        baseline_has_error = bool(_SQL_RE.search(baseline))
        if baseline_has_error:
            return  # pre-existing error, cannot attribute to our probe

        for param, mutated in iter_param_injections(ctx.url, "'"):
            try:
                resp = await ctx.client.get(mutated)
            except Exception:  # noqa: BLE001
                continue
            body = response_text(resp)
            match = _SQL_RE.search(body)
            if match:
                self._report(
                    ctx,
                    title=f"Possible SQL injection in parameter '{param}'",
                    severity=Severity.HIGH,
                    description=(
                        "Injecting a single quote triggered a database error, "
                        "indicating unsanitized input reaches a SQL query."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-89",
                    owasp="A03:2021 Injection",
                    evidence=f"Error signature matched: {match.group(0)!r}",
                    remediation=(
                        "Use parameterized queries / prepared statements; never "
                        "concatenate user input into SQL."
                    ),
                    url=mutated,
                    tags=["sqli", "injection", "active"],
                )

