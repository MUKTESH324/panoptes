from panoptes.models import Confidence, Finding, Severity
from panoptes.utils.dedupe import dedupe_findings
from panoptes.utils.inject import has_query_params, iter_param_injections


def test_iter_param_injections():
    url = "https://example.com/s?q=a&page=2"
    out = dict(iter_param_injections(url, "PAYLOAD"))
    assert set(out) == {"q", "page"}
    assert "q=PAYLOAD" in out["q"]
    assert "page=2" in out["q"]  # other params preserved


def test_has_query_params():
    assert has_query_params("https://example.com/?a=1")
    assert not has_query_params("https://example.com/")


def _f(sev, conf=Confidence.FIRM, title="t"):
    return Finding(plugin="p", title=title, severity=sev, description="d",
                   url="https://example.com/a", confidence=conf)


def test_dedupe_keeps_strongest():
    findings = [_f(Severity.LOW), _f(Severity.HIGH), _f(Severity.MEDIUM)]
    out = dedupe_findings(findings)
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH


def test_dedupe_sorted_by_severity_desc():
    out = dedupe_findings([_f(Severity.LOW, title="a"), _f(Severity.CRITICAL, title="b")])
    assert [f.severity for f in out] == [Severity.CRITICAL, Severity.LOW]


def _site_wide(url):
    return Finding(plugin="cookie-flags", title="Cookie 'x' insecure", severity=Severity.LOW,
                   description="d", url=url, site_wide=True)


def test_site_wide_findings_collapse_per_host():
    findings = [
        _site_wide("https://example.com/a.js"),
        _site_wide("https://example.com/b.png"),
        _site_wide("https://example.com/c/d.svg?v=1"),
    ]
    out = dedupe_findings(findings)
    assert len(out) == 1
    assert out[0].occurrences == 3


def test_site_wide_distinguishes_hosts():
    out = dedupe_findings([
        _site_wide("https://a.example.com/x"),
        _site_wide("https://b.example.com/x"),
    ])
    assert len(out) == 2


def test_per_url_findings_not_collapsed():
    a = Finding(plugin="reflected-xss", title="XSS", severity=Severity.HIGH, description="d",
                url="https://example.com/s?q=1")
    b = Finding(plugin="reflected-xss", title="XSS", severity=Severity.HIGH, description="d",
                url="https://example.com/other?q=1")
    assert len(dedupe_findings([a, b])) == 2
