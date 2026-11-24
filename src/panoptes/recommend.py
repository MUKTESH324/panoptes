"""Recommended next steps.

Turns what Panoptes observed (findings + open ports) into a prioritized,
human-actionable checklist of manual follow-ups and the tools a tester would
reach for next. Everything here is *advisory* — it suggests authorized
verification steps, it does not perform them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from .models import Finding, Severity
from .portscan import PortScanResult


@dataclass
class Recommendation:
    title: str
    priority: Severity
    detail: str
    tools: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "priority": self.priority.name.lower(),
            "detail": self.detail,
            "tools": self.tools,
        }


# Follow-ups keyed by the plugin that produced a finding.
_FINDING_RECS = {
    "reflected-xss": Recommendation(
        "Confirm and weaponize the reflected XSS",
        Severity.HIGH,
        "Build a minimal PoC in the vulnerable parameter, check the injection "
        "context (HTML / attribute / JS), and test whether a CSP blocks it. If "
        "cookies lack HttpOnly, demonstrate session theft for the report.",
        ["browser devtools", "XSS Hunter"],
    ),
    "sqli-error": Recommendation(
        "Validate the SQL injection safely",
        Severity.HIGH,
        "Manually confirm with boolean/time-based payloads before anything "
        "heavier. Only run automated exploitation within your authorized scope "
        "and rules of engagement.",
        ["sqlmap (authorized scope only)"],
    ),
    "open-redirect": Recommendation(
        "Chain the open redirect",
        Severity.MEDIUM,
        "Check whether the redirect is reachable from an OAuth/SSO flow or a "
        "password-reset link, which can turn it into token theft or account "
        "takeover.",
        [],
    ),
    "cors-misconfig": Recommendation(
        "Prove the CORS data exposure",
        Severity.HIGH,
        "From a test origin, issue a credentialed cross-origin request and show "
        "that an authenticated response body is readable.",
        ["curl", "browser PoC page"],
    ),
}

# General methodology that is almost always worth doing on a web target.
_GENERAL = [
    Recommendation(
        "Enumerate subdomains and expand the attack surface",
        Severity.MEDIUM,
        "Discover related hosts; add in-scope ones to --scope and re-hunt.",
        ["subfinder", "amass", "crt.sh"],
    ),
    Recommendation(
        "Content & endpoint discovery",
        Severity.MEDIUM,
        "Brute-force hidden paths, backups and admin panels, and parse JS for "
        "routes, API endpoints and leaked secrets.",
        ["ffuf", "gobuster", "LinkFinder"],
    ),
    Recommendation(
        "Run a templated vulnerability sweep",
        Severity.LOW,
        "Complement Panoptes with a CVE/template scanner for known issues.",
        ["nuclei"],
    ),
    Recommendation(
        "Test TLS configuration",
        Severity.LOW,
        "Check protocol versions, ciphers and certificate issues.",
        ["testssl.sh", "sslscan"],
    ),
]


def recommend(
    findings: List[Finding], ports: Optional[PortScanResult] = None
) -> List[Recommendation]:
    recs: List[Recommendation] = []
    seen_titles: Set[str] = set()

    def add(rec: Recommendation) -> None:
        if rec.title not in seen_titles:
            seen_titles.add(rec.title)
            recs.append(rec)

    plugins = {f.plugin for f in findings}
    for plugin, rec in _FINDING_RECS.items():
        if plugin in plugins:
            add(rec)

    if ports:
        for op in ports.open_ports:
            prec = _port_recommendation(op.service, op.port)
            if prec:
                add(prec)
        if not ports.open_ports:
            add(Recommendation(
                "No common ports open",
                Severity.INFO,
                "Only the scanned common ports were checked; consider a wider "
                "port range if the rules of engagement allow it.",
                ["nmap -p-"],
            ))

    for rec in _GENERAL:
        add(rec)

    recs.sort(key=lambda r: (-int(r.priority), r.title))
    return recs


def _port_recommendation(service: str, port: int) -> Optional[Recommendation]:
    svc = service.lower()
    if svc in ("mysql", "postgresql", "mssql", "oracle", "mongodb", "redis",
               "memcached", "elasticsearch"):
        return Recommendation(
            f"Investigate exposed {service} on port {port}",
            Severity.HIGH,
            "Verify the datastore requires authentication and is not reachable "
            "from the internet; many default to no auth.",
            [],
        )
    if svc == "ssh":
        return Recommendation(
            "Review the SSH service",
            Severity.LOW,
            "Note the version for known CVEs; confirm key-based auth and that "
            "password login / weak algorithms are disabled.",
            ["ssh-audit"],
        )
    if svc in ("ftp", "telnet"):
        return Recommendation(
            f"Check the {service} service",
            Severity.MEDIUM,
            "Cleartext protocol — test for anonymous/default access and prefer "
            "disabling it in favour of encrypted alternatives.",
            [],
        )
    if svc in ("http", "http-alt", "http-proxy", "https-alt") and port not in (80, 443):
        return Recommendation(
            f"Inspect the web service on port {port}",
            Severity.MEDIUM,
            "Non-standard web port — point a hunt at it too; it may host an "
            "admin panel or a separate app.",
            ["panoptes hunt"],
        )
    if svc == "docker":
        return Recommendation(
            "Exposed Docker API",
            Severity.HIGH,
            "An unauthenticated Docker API typically means remote host "
            "compromise; confirm it is firewalled and TLS-authenticated.",
            [],
        )
    return None
