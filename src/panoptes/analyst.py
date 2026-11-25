"""AI analyst — LLM synthesis of a hunt's findings.

Inspired by the "LLM reasons over the engagement" idea from autonomous
red-team frameworks, but kept strictly **defensive and analytical**: it does not
plan or run exploitation. It sends a compact, non-sensitive digest of the hunt
(finding titles, severities, counts, chains, open ports) to the configured LLM
provider and returns an executive summary + prioritized risks + remediation
roadmap for the report.

It is opt-in (``--ai-report``) and only runs when an AI provider is enabled, so
nothing leaves the host unless the operator chooses it (same as AI payloads).
"""

from __future__ import annotations

from typing import List

from .models import Severity


def build_digest(hunt) -> str:
    """A compact, non-sensitive digest of the hunt for the LLM."""
    lines: List[str] = [f"Target: {hunt.target}", f"URLs scanned: {hunt.urls_scanned}"]
    if hunt.signals:
        lines.append(f"Tech: {', '.join(hunt.signals.get('tech') or []) or 'unknown'}; "
                     f"WAF: {hunt.signals.get('waf') or 'none'}")

    counts = {s: 0 for s in Severity}
    for f in hunt.findings:
        counts[f.severity] += 1
    lines.append("Finding counts by severity: "
                 + ", ".join(f"{s.name.lower()}={counts[s]}" for s in sorted(Severity, reverse=True)))

    lines.append("\nFindings (title | severity | confidence | cwe):")
    for f in hunt.findings[:80]:  # cap the prompt size
        lines.append(f"- {f.title} | {f.severity.name.lower()} | {f.confidence} | {f.cwe or '-'}")

    if hunt.chains:
        lines.append("\nInferred exploit chains:")
        for c in hunt.chains:
            lines.append(f"- {c.name} ({c.severity.name.lower()})")

    if hunt.ports is not None and hunt.ports.open_ports:
        ports = ", ".join(f"{p.port}/{p.service}" for p in hunt.ports.open_ports)
        lines.append(f"\nOpen ports: {ports}")

    return "\n".join(lines)


async def analyze_hunt(hunt, provider) -> str:
    """Return the LLM analyst write-up, or '' if unavailable."""
    if not hunt.findings:
        return ""
    digest = build_digest(hunt)
    try:
        return (await provider.analyze(digest)).strip()
    except Exception:  # noqa: BLE001
        return ""
