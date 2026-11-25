"""Exploit-chain inference.

Individual findings are often more dangerous together. The chain builder
applies declarative rules over a scan's findings and emits higher-level
"chains" that explain how issues compound — the A→B reasoning a human analyst
would do manually.

Rules are intentionally conservative: a chain is only emitted when all of its
component conditions are present on the same host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List

from .models import Finding, Severity
from .utils.urls import hostname


@dataclass
class Chain:
    name: str
    severity: Severity
    narrative: str
    components: List[str] = field(default_factory=list)  # finding fingerprints

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity.name.lower(),
            "narrative": self.narrative,
            "components": self.components,
        }


@dataclass
class _Rule:
    name: str
    severity: Severity
    narrative: str
    predicate: Callable[[Dict[str, List[Finding]]], List[Finding]]


def _by_plugin(findings: List[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for f in findings:
        out.setdefault(f.plugin, []).append(f)
    return out


def _has_csp_missing(idx: Dict[str, List[Finding]]) -> bool:
    return any("Content-Security-Policy" in f.title for f in idx.get("security-headers", []))


# -- rules ----------------------------------------------------------------

def _rule_xss_no_csp(idx):
    xss = idx.get("reflected-xss", [])
    if xss and _has_csp_missing(idx):
        comps = [xss[0]] + [f for f in idx.get("security-headers", [])
                            if "Content-Security-Policy" in f.title][:1]
        return comps
    return []


def _rule_redirect_to_takeover(idx):
    red = idx.get("open-redirect", [])
    return red[:1] if red else []


def _rule_sqli_with_errors(idx):
    sqli = idx.get("sqli-error", [])
    info = [f for f in idx.get("info-disclosure", []) if "stack trace" in f.title.lower()]
    if sqli and info:
        return sqli[:1] + info[:1]
    return []


def _rule_cors_with_cookie(idx):
    cors = idx.get("cors-misconfig", [])
    cookie = idx.get("cookie-flags", [])
    if cors and cookie:
        return cors[:1] + cookie[:1]
    return []


_RULES = [
    _Rule(
        name="Reflected XSS with no CSP",
        severity=Severity.CRITICAL,
        narrative=(
            "A reflected-XSS sink exists and the page ships no Content-Security-"
            "Policy, so an injected script has nothing to stop it — raising this "
            "from a reflected XSS to reliable client-side code execution."
        ),
        predicate=_rule_xss_no_csp,
    ),
    _Rule(
        name="Open redirect → credential/token theft",
        severity=Severity.HIGH,
        narrative=(
            "An open redirect can be chained into OAuth token theft or convincing "
            "phishing by bouncing victims through the trusted origin to an "
            "attacker-controlled destination."
        ),
        predicate=_rule_redirect_to_takeover,
    ),
    _Rule(
        name="SQL injection amplified by verbose errors",
        severity=Severity.HIGH,
        narrative=(
            "An injectable parameter combined with leaked database error output "
            "gives an attacker both the entry point and the feedback channel "
            "needed to iterate toward data extraction."
        ),
        predicate=_rule_sqli_with_errors,
    ),
    _Rule(
        name="CORS exposure of cookie-authenticated data",
        severity=Severity.HIGH,
        narrative=(
            "A permissive CORS policy together with cookie-based sessions lets a "
            "malicious origin read authenticated responses on the victim's behalf."
        ),
        predicate=_rule_cors_with_cookie,
    ),
]


class ChainBuilder:
    def build(self, findings: List[Finding]) -> List[Chain]:
        chains: List[Chain] = []
        # Group by host so a chain only links issues on the same origin.
        by_host: Dict[str, List[Finding]] = {}
        for f in findings:
            by_host.setdefault(hostname(f.url), []).append(f)

        for host_findings in by_host.values():
            idx = _by_plugin(host_findings)
            for rule in _RULES:
                comps = rule.predicate(idx)
                if comps:
                    chains.append(
                        Chain(
                            name=rule.name,
                            severity=rule.severity,
                            narrative=rule.narrative,
                            components=[f.fingerprint for f in comps],
                        )
                    )
        chains.sort(key=lambda c: -int(c.severity))
        return chains

