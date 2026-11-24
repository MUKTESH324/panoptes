"""Finding validation gate.

Before a finding is reported, it passes through a set of validation questions
(a deterministic, rule-based take on a triage checklist). Each question the
finding passes raises its validation score; the score maps to a verdict:

  * ``confirmed``     — strong evidence, report with confidence
  * ``needs-review``  — plausible, flag for a human
  * ``likely-fp``     — weak, drop in strict mode

This reduces the noise that makes raw scanner output painful, without silently
discarding anything (dropped findings are returned separately, never deleted).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .models import Confidence, Finding, Severity

# Plugins that carry a unique, reflected marker => strong reproducibility signal.
_REPRODUCIBLE_PLUGINS = {"reflected-xss", "sqli-error", "open-redirect", "cors-misconfig"}


@dataclass
class Verdict:
    finding: Finding
    score: int
    max_score: int
    verdict: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.finding.fingerprint,
            "title": self.finding.title,
            "score": f"{self.score}/{self.max_score}",
            "verdict": self.verdict,
            "reasons": self.reasons,
        }


_QUESTIONS = [
    "has_evidence",
    "confidence_firm_or_better",
    "reproducible_probe",
    "severity_actionable",
    "has_remediation",
    "mapped_to_cwe",
    "specific_location",
]


def _evaluate_one(f: Finding) -> Verdict:
    reasons: List[str] = []
    score = 0

    if f.evidence.strip():
        score += 1
        reasons.append("has concrete evidence")
    if f.confidence >= Confidence.FIRM:
        score += 1
        reasons.append(f"confidence is {f.confidence}")
    if f.plugin in _REPRODUCIBLE_PLUGINS:
        score += 1
        reasons.append("active probe with reproducible marker")
    if f.severity >= Severity.LOW:
        score += 1
        reasons.append("severity is actionable")
    if f.remediation.strip():
        score += 1
        reasons.append("remediation available")
    if f.cwe:
        score += 1
        reasons.append(f"mapped to {f.cwe}")
    if f.url and ("?" in f.url or f.plugin != "security-headers"):
        score += 1
        reasons.append("specific location")

    max_score = len(_QUESTIONS)
    if score >= 5:
        verdict = "confirmed"
    elif score >= 3:
        verdict = "needs-review"
    else:
        verdict = "likely-fp"
    return Verdict(finding=f, score=score, max_score=max_score, verdict=verdict, reasons=reasons)


@dataclass
class ValidationResult:
    confirmed: List[Finding]
    needs_review: List[Finding]
    likely_fp: List[Finding]
    verdicts: List[Verdict]

    @property
    def kept(self) -> List[Finding]:
        return self.confirmed + self.needs_review

    def summary(self) -> dict:
        return {
            "confirmed": len(self.confirmed),
            "needs_review": len(self.needs_review),
            "likely_fp": len(self.likely_fp),
        }


class ValidationGate:
    """Scores findings and partitions them by verdict."""

    def __init__(self, strict: bool = False) -> None:
        # strict => likely-fp findings are dropped from the kept set.
        self.strict = strict

    def evaluate(self, findings: List[Finding]) -> ValidationResult:
        verdicts = [_evaluate_one(f) for f in findings]
        confirmed = [v.finding for v in verdicts if v.verdict == "confirmed"]
        review = [v.finding for v in verdicts if v.verdict == "needs-review"]
        fp = [v.finding for v in verdicts if v.verdict == "likely-fp"]
        return ValidationResult(confirmed=confirmed, needs_review=review,
                                likely_fp=fp, verdicts=verdicts)
