"""Collapse duplicate findings by fingerprint, keeping the strongest."""

from __future__ import annotations

from typing import Dict, List

from ..models import Finding


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    best: Dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        existing = best.get(key)
        if existing is None or (f.severity, f.confidence) > (
            existing.severity,
            existing.confidence,
        ):
            best[key] = f
    # Stable order: severity desc, then title.
    return sorted(best.values(), key=lambda f: (-int(f.severity), f.title))
