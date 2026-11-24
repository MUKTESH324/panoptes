"""Attack planner.

Turns lightweight recon signals (observed tech stack, WAF, whether parameters
exist) into an ordered, phased plan of which check plugins to run. This is the
"think before you swing" step: passive recon first, then only the active checks
that the surface actually warrants.

The planner is rule-based and deterministic by default (so it is testable and
predictable). When an AI provider is supplied it may *reorder/annotate* the
plan, but it can never add a plugin that is not installed or bypass scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

# Plugin classification used for phasing.
PASSIVE_PLUGINS = ["security-headers", "cookie-flags", "info-disclosure", "csrf", "jwt"]
ACTIVE_PLUGINS = ["cors-misconfig", "open-redirect", "reflected-xss", "sqli-error"]

_WAF_SIGNS = {
    "cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "akamai": ["akamai", "x-akamai"],
    "aws-waf": ["x-amzn-waf", "awselb"],
    "imperva": ["x-iinfo", "incap_ses"],
}


@dataclass
class Signals:
    tech: List[str] = field(default_factory=list)
    waf: Optional[str] = None
    has_params: bool = False
    url_count: int = 0


@dataclass
class Phase:
    name: str
    plugins: List[str]
    rationale: str


@dataclass
class Plan:
    phases: List[Phase] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def all_plugins(self) -> List[str]:
        seen: List[str] = []
        for ph in self.phases:
            for p in ph.plugins:
                if p not in seen:
                    seen.append(p)
        return seen

    def to_dict(self) -> Dict[str, object]:
        return {
            "phases": [
                {"name": p.name, "plugins": p.plugins, "rationale": p.rationale}
                for p in self.phases
            ],
            "notes": self.notes,
        }


def recon_signals(pages: Dict[str, httpx.Response]) -> Signals:
    """Derive signals from already-fetched pages."""
    sig = Signals(url_count=len(pages))
    tech: set = set()
    for url, resp in pages.items():
        if "?" in url and url.split("?", 1)[1]:
            sig.has_params = True
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if headers.get(h):
                tech.add(_clean_tech(headers[h]))
        blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        if sig.waf is None:
            for name, signs in _WAF_SIGNS.items():
                if any(s in blob for s in signs):
                    sig.waf = name
                    break
    sig.tech = sorted(t for t in tech if t)
    return sig


def _clean_tech(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:60]


class Planner:
    def __init__(self, available: Optional[List[str]] = None) -> None:
        self.available = set(available) if available is not None else None

    def _filter(self, names: List[str]) -> List[str]:
        if self.available is None:
            return names
        return [n for n in names if n in self.available]

    def plan(self, signals: Signals) -> Plan:
        plan = Plan()
        plan.phases.append(
            Phase(
                name="recon",
                plugins=self._filter(PASSIVE_PLUGINS),
                rationale="Passive checks first: no injection, just observe headers, "
                "cookies and leaks.",
            )
        )

        if signals.has_params:
            active = self._filter(ACTIVE_PLUGINS)
            rationale = "Parameters present — probe injection points."
        else:
            # No params: only origin-reflection CORS is worth an active probe.
            active = self._filter(["cors-misconfig"])
            rationale = "No query parameters discovered — limit active probing to CORS."
        if active:
            plan.phases.append(Phase(name="exploit", plugins=active, rationale=rationale))

        if signals.tech:
            plan.notes.append(f"Observed tech: {', '.join(signals.tech)}")
        if signals.waf:
            plan.notes.append(
                f"WAF detected: {signals.waf} — findings may need manual confirmation; "
                "consider lowering request rate."
            )
        if not signals.has_params:
            plan.notes.append("No parameters found; injection checks were de-prioritized.")
        return plan
