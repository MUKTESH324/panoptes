"""SARIF 2.1.0 report — consumable by GitHub code scanning and most CI tools."""

from __future__ import annotations

import json
from typing import Dict, List

from .. import __version__
from ..models import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_sarif(result: ScanResult) -> str:
    rules: Dict[str, dict] = {}
    sarif_results: List[dict] = []

    for f in result.findings:
        rule_id = f.plugin
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.title},
                "properties": {
                    "tags": [t for t in [f.owasp, f.cwe] if t],
                    "security-severity": _security_severity(f.severity),
                },
            }
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.url},
                        }
                    }
                ],
                "partialFingerprints": {"panoptes/v1": f.fingerprint},
                "properties": {
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "confidence": str(f.confidence),
                    "evidence": f.evidence,
                },
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Panoptes",
                        "version": __version__,
                        "informationUri": "https://example.invalid/panoptes",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _security_severity(sev: Severity) -> str:
    return {
        Severity.INFO: "0.0",
        Severity.LOW: "3.0",
        Severity.MEDIUM: "5.5",
        Severity.HIGH: "8.0",
        Severity.CRITICAL: "9.5",
    }[sev]
