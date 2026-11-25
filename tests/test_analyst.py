"""AI analyst: digest, analysis, provider wiring, report integration."""

from __future__ import annotations

from panoptes.ai.base import AIProvider, NullProvider
from panoptes.ai.registry import FailoverProvider
from panoptes.analyst import analyze_hunt, build_digest
from panoptes.hunt import HuntResult
from panoptes.models import Confidence, Finding, Severity
from panoptes.reporting.hunt import render_hunt_html, render_hunt_markdown
from panoptes.validation import ValidationResult


class _MockProvider(AIProvider):
    name = "mock"

    def __init__(self, text: str = "EXEC SUMMARY: looks risky") -> None:
        self.text = text
        self.seen = None

    async def generate(self, request):
        return []

    async def analyze(self, prompt: str, system: str = "") -> str:
        self.seen = prompt
        return self.text


def _f(plugin, title, sev, url, cwe=None):
    return Finding(plugin=plugin, title=title, severity=sev, description="d",
                   url=url, confidence=Confidence.FIRM, cwe=cwe)


def _hunt(findings):
    h = HuntResult(target="https://a.example.com")
    h.finished_at = h.started_at + 1
    h.urls_scanned = 2
    h.validation = ValidationResult(confirmed=[], needs_review=findings,
                                    likely_fp=[], verdicts=[])
    return h


async def test_build_digest_has_findings_and_counts():
    hunt = _hunt([_f("xss", "Reflected XSS", Severity.HIGH, "https://a/x", "CWE-79")])
    digest = build_digest(hunt)
    assert "Reflected XSS" in digest
    assert "high=1" in digest
    assert hunt.target in digest


async def test_analyze_hunt_returns_provider_text():
    provider = _MockProvider("SUMMARY TEXT")
    hunt = _hunt([_f("x", "Finding Title", Severity.LOW, "https://a/x")])
    out = await analyze_hunt(hunt, provider)
    assert out == "SUMMARY TEXT"
    assert provider.seen and "Finding Title" in provider.seen


async def test_analyze_hunt_empty_without_findings():
    assert await analyze_hunt(_hunt([]), _MockProvider()) == ""


async def test_null_provider_analyze_is_empty():
    assert await NullProvider().analyze("anything") == ""


async def test_failover_analyze_picks_first_nonempty():
    class _Empty(NullProvider):
        async def analyze(self, prompt, system=""):
            return ""

    fp = FailoverProvider([_Empty(), _MockProvider("GOOD")])
    assert await fp.analyze("x") == "GOOD"


def test_reports_include_ai_section():
    hunt = _hunt([_f("x", "t", Severity.LOW, "https://a/x")])
    hunt.ai_analysis = "My executive summary here"
    md = render_hunt_markdown(hunt)
    html = render_hunt_html(hunt)
    assert "AI analyst summary" in md and "My executive summary here" in md
    assert "AI analyst summary" in html and "My executive summary here" in html
