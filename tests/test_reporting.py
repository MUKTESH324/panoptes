import json

from argus.models import Confidence, Finding, ScanResult, Severity
from argus.reporting import render


def _result():
    r = ScanResult(target="https://example.com")
    r.finished_at = r.started_at + 2
    r.urls_scanned = 3
    r.findings = [
        Finding(
            plugin="security-headers",
            title="CSP missing",
            severity=Severity.MEDIUM,
            description="no csp",
            url="https://example.com/",
            confidence=Confidence.CERTAIN,
            cwe="CWE-693",
            owasp="A05:2021 Security Misconfiguration",
            evidence="no header",
            remediation="add csp",
            references=["https://owasp.org/csp"],
        )
    ]
    return r


def test_render_json_roundtrip():
    out = render(_result(), "json")
    data = json.loads(out)
    assert data["target"] == "https://example.com"
    assert data["findings"][0]["severity"] == "medium"


def test_render_sarif_valid_shape():
    out = render(_result(), "sarif")
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus"
    assert run["results"][0]["level"] == "warning"
    assert run["results"][0]["ruleId"] == "security-headers"


def test_render_markdown_contains_sections():
    out = render(_result(), "markdown")
    assert "# Argus scan report" in out
    assert "CSP missing" in out
    assert "Remediation" in out


def test_render_html_escapes_and_renders():
    r = _result()
    r.findings[0].title = "<script>alert(1)</script>"
    out = render(r, "html")
    assert "<!doctype html>" in out
    assert "<script>alert(1)</script>" not in out  # escaped
    assert "&lt;script&gt;" in out


def test_render_unknown_format_raises():
    import pytest

    with pytest.raises(ValueError):
        render(_result(), "pdf")
