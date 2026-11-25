"""Severity-grouped HTML hunt report."""

from __future__ import annotations

from panoptes.chains import Chain
from panoptes.hunt import HuntResult
from panoptes.models import Confidence, Finding, Severity
from panoptes.reporting.hunt import render_hunt, render_hunt_html
from panoptes.validation import ValidationResult


def _f(plugin, title, sev, url, conf=Confidence.FIRM, cwe=None, tags=None):
    return Finding(plugin=plugin, title=title, severity=sev, description="desc",
                   url=url, confidence=conf, cwe=cwe, tags=tags or [])


def _hunt(findings, chains=None):
    h = HuntResult(target="https://a.example.com")
    h.finished_at = h.started_at + 1
    h.urls_scanned = 3
    confirmed = [f for f in findings if f.confidence == Confidence.CERTAIN]
    rest = [f for f in findings if f.confidence != Confidence.CERTAIN]
    h.validation = ValidationResult(confirmed=confirmed, needs_review=rest,
                                    likely_fp=[], verdicts=[])
    h.chains = chains or []
    return h


def test_hunt_html_structure_and_sections():
    findings = [
        _f("xss-verified", "Browser-confirmed reflected XSS", Severity.HIGH,
           "https://a.example.com/s?q=1", Confidence.CERTAIN, "CWE-79",
           ["xss", "browser-verified"]),
        _f("security-headers", "CSP missing", Severity.MEDIUM,
           "https://a.example.com/x", cwe="CWE-693"),
        _f("security-headers", "CSP missing", Severity.MEDIUM,
           "https://b.example.com/y", cwe="CWE-693"),  # same issue, other host
        _f("access-control", "Possible vertical privilege escalation", Severity.HIGH,
           "https://a.example.com/admin", cwe="CWE-269", tags=["authz", "access-control"]),
    ]
    chain = Chain(name="Reflected XSS with no CSP", severity=Severity.CRITICAL,
                  narrative="bad combo", components=["abc123"])
    html = render_hunt_html(_hunt(findings, [chain]))

    assert "<!doctype html>" in html
    # confirmed section surfaced first
    assert "Confirmed findings" in html
    assert "Browser-confirmed reflected XSS" in html
    assert 'class="badge confirmed"' in html
    # chains surfaced
    assert "Exploit chains" in html and "Reflected XSS with no CSP" in html
    # authz badge surfaced
    assert 'class="badge authz"' in html
    # cross-host dedup: the two "CSP missing" findings collapse to one card of 2
    assert "Affected (2)" in html


def test_hunt_html_escapes_content():
    html = render_hunt_html(_hunt([_f("x", "<script>alert(1)</script>",
                                      Severity.LOW, "https://a.example.com/x")]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_hunt_dispatch_html():
    html = render_hunt(_hunt([_f("x", "t", Severity.LOW, "https://a.example.com/x")]), "html")
    assert "<!doctype html>" in html


def test_render_hunt_rejects_unknown_format():
    import pytest
    with pytest.raises(ValueError):
        render_hunt(_hunt([]), "pdf")
