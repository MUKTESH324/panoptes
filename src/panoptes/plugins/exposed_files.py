"""Active check: exposed sensitive files and endpoints (content discovery).

Requests a curated list of commonly-leaked paths at the site root and flags the
ones that return a telltale signature — source-control dirs, environment files,
backups, status/debug endpoints. Non-destructive (GET only), and it probes each
host **once per scan**, not once per crawled URL.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlsplit

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

# (path, severity, signature-regex-or-None, title)
_PROBES: List[Tuple[str, Severity, Optional[str], str]] = [
    ("/.git/config", Severity.HIGH, r"\[core\]|repositoryformatversion", "Exposed .git repository"),
    ("/.git/HEAD", Severity.HIGH, r"ref:\s*refs/", "Exposed .git repository"),
    ("/.env", Severity.HIGH, r"(?mi)^[A-Z0-9_]+=|APP_KEY=|DB_PASSWORD=|SECRET", "Exposed .env file"),
    ("/.svn/entries", Severity.HIGH, r"^\d+|svn", "Exposed .svn directory"),
    ("/.hg/requires", Severity.MEDIUM, r"revlog|dotencode", "Exposed Mercurial repository"),
    ("/.DS_Store", Severity.LOW, r"Bud1|\x00\x00\x00\x01Bud1", "Exposed .DS_Store"),
    ("/server-status", Severity.MEDIUM, r"Apache Server Status|Server Version", "Apache server-status exposed"),
    ("/actuator", Severity.MEDIUM, r"\"_links\"|health|metrics", "Spring Boot actuator exposed"),
    ("/actuator/env", Severity.HIGH, r"\"propertySources\"|systemEnvironment", "Spring actuator /env exposed"),
    ("/phpinfo.php", Severity.MEDIUM, r"phpinfo\(\)|PHP Version", "phpinfo() exposed"),
    ("/.htaccess", Severity.MEDIUM, r"RewriteEngine|Order allow", "Exposed .htaccess"),
    ("/wp-config.php.bak", Severity.HIGH, r"DB_PASSWORD|<\?php", "Exposed wp-config backup"),
    ("/config.php.bak", Severity.HIGH, r"<\?php|password", "Exposed PHP config backup"),
    ("/.well-known/security.txt", Severity.INFO, r"Contact:|Policy:", "security.txt present"),
]


@register
class ExposedFiles(Plugin):
    name = "exposed-files"
    description = "Probes common sensitive paths (.git, .env, backups, debug endpoints)."
    passive = False

    def __init__(self) -> None:
        self._seen_origins: Set[str] = set()

    async def check(self, ctx: ScanContext) -> None:
        parts = urlsplit(ctx.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._seen_origins:
            return
        self._seen_origins.add(origin)

        for path, severity, signature, title in _PROBES:
            url = origin + path
            try:
                resp = await ctx.client.get(url)
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code != 200:
                continue
            body = response_text(resp)
            if signature and not re.search(signature, body):
                continue
            # security.txt presence is informational, not a weakness.
            is_info = severity == Severity.INFO
            self._report(
                ctx,
                title=title if not is_info else "security.txt is published (good practice)",
                severity=severity,
                description=(
                    f"The path {path} is reachable and returned matching content. "
                    + ("This is a best-practice file, not a weakness."
                       if is_info else
                       "Exposed source control, secrets, backups or debug endpoints "
                       "can leak credentials and source code.")
                ),
                confidence=Confidence.FIRM if signature else Confidence.TENTATIVE,
                cwe=None if is_info else "CWE-538",
                owasp=None if is_info else "A05:2021 Security Misconfiguration",
                evidence=f"GET {url} -> 200" + (" (signature matched)" if signature else ""),
                remediation=(
                    "Remove the file from the web root or block it at the server; "
                    "rotate any leaked secrets."
                ) if not is_info else "No action needed.",
                url=url,
                tags=["exposure", "discovery", "active"],
                site_wide=True,
            )

