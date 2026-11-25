"""Active check: OS command injection.

Non-destructive detection. The only command used is ``echo``. The payload wraps
a benign ``echo`` substitution between two unique markers, e.g.
``PRE$(echo MID)POST``. If the input is merely reflected, the response shows the
literal ``PRE$(echo MID)POST``; only if the shell *executes* the substitution
does the response contain the concatenated ``PREMIDPOST`` — which is the
detection signal (it cannot appear by reflection). No sleeps, no destructive
commands, no file access.
"""

from __future__ import annotations

import secrets

from ..models import Confidence, Severity
from ..utils.http import response_text
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register


@register
class CommandInjection(Plugin):
    name = "command-injection"
    description = "Detects OS command injection via a benign echo-substitution probe."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        pre = "cx" + secrets.token_hex(3)
        mid = secrets.token_hex(3)
        post = secrets.token_hex(3) + "xc"
        expected = pre + mid + post  # appears only if `echo mid` is executed

        payloads = [
            pre + "$(echo " + mid + ")" + post,
            pre + "`echo " + mid + "`" + post,
        ]
        for payload in payloads:
            for param, mutated in iter_param_injections(ctx.url, payload):
                try:
                    resp = await ctx.client.get(mutated)
                except Exception:  # noqa: BLE001
                    continue
                if expected in response_text(resp):
                    self._report(
                        ctx,
                        title=f"OS command injection in parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            "Input in this parameter was executed by a shell: a "
                            "benign echo substitution produced its concatenated "
                            "output in the response, indicating command injection "
                            "(remote code execution)."
                        ),
                        confidence=Confidence.FIRM,
                        cwe="CWE-78",
                        owasp="A03:2021 Injection",
                        evidence=f"Payload {payload!r} executed; response contained {expected!r}.",
                        remediation=(
                            "Never pass user input to a shell. Use parameterized "
                            "APIs / exec with an argument array, validate against "
                            "an allowlist, and avoid shell interpreters entirely."
                        ),
                        url=mutated,
                        tags=["command-injection", "rce", "injection", "active"],
                    )
                    return

