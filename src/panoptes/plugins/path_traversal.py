"""Active check: path traversal / local file inclusion (LFI).

Non-destructive: injects traversal sequences targeting world-readable system
files (/etc/passwd, Windows win.ini) into file-like parameters and looks for the
file's signature in the response. It only *reads* standard files to prove the
sink; it does not write, include remote resources, or target sensitive data.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Severity
from ..utils.inject import has_query_params, iter_param_injections
from .base import Plugin, ScanContext, register

_FILE_PARAM_NAMES = {
    "file", "filename", "path", "page", "doc", "document", "template", "tpl",
    "include", "inc", "view", "folder", "dir", "download", "read", "load",
    "name", "lang", "locale", "style", "pdf", "img", "image", "cat", "action",
    "item", "content", "layout", "module", "class", "conf", "config",
}

_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../../../windows/win.ini",
]
_SIGNATURE = re.compile(r"root:.*?:0:0:|\[fonts\]|\[extensions\]|16-bit app support")


@register
class PathTraversal(Plugin):
    name = "path-traversal"
    description = "Detects path traversal / local file inclusion in file-like parameters."
    passive = False

    async def check(self, ctx: ScanContext) -> None:
        if not has_query_params(ctx.url):
            return
        targets = _file_like_params(ctx.url)
        if not targets:
            return
        baseline = _safe_text(ctx.response) if ctx.response is not None else ""
        if _SIGNATURE.search(baseline):
            return  # signature already present; cannot attribute to our probe

        for payload in _PAYLOADS:
            for param, mutated in iter_param_injections(ctx.url, payload):
                if param not in targets:
                    continue
                try:
                    resp = await ctx.client.get(mutated)
                except Exception:  # noqa: BLE001
                    continue
                m = _SIGNATURE.search(_safe_text(resp))
                if m:
                    self._report(
                        ctx,
                        title=f"Path traversal / local file inclusion in parameter '{param}'",
                        severity=Severity.HIGH,
                        description=(
                            "A traversal sequence in this parameter returned the "
                            "contents of a system file, confirming the server reads "
                            "an attacker-controlled path."
                        ),
                        confidence=Confidence.FIRM,
                        cwe="CWE-22",
                        owasp="A01:2021 Broken Access Control",
                        evidence=f"Payload {payload!r} returned file signature {m.group(0)[:40]!r}.",
                        remediation=(
                            "Resolve and canonicalize paths, confine to a base "
                            "directory, reject traversal sequences, and prefer an "
                            "allowlist of identifiers over raw filenames."
                        ),
                        url=mutated,
                        tags=["lfi", "path-traversal", "injection", "active"],
                    )
                    return


def _file_like_params(url: str) -> set:
    out = set()
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name.lower() in _FILE_PARAM_NAMES or "/" in value or "." in value:
            out.add(name)
    return out


def _safe_text(response) -> str:
    try:
        return response.text[:500_000]
    except Exception:  # noqa: BLE001
        return ""
