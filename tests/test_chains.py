from panoptes.chains import ChainBuilder
from panoptes.models import Finding, Severity


def _f(plugin, title, url="https://example.com/"):
    return Finding(plugin=plugin, title=title, severity=Severity.MEDIUM,
                   description="d", url=url)


def test_xss_no_csp_chain():
    findings = [
        _f("reflected-xss", "Reflected input not HTML-encoded in parameter 'q'",
           "https://example.com/s?q=1"),
        _f("security-headers", "Content-Security-Policy header is missing"),
    ]
    chains = ChainBuilder().build(findings)
    names = [c.name for c in chains]
    assert "Reflected XSS with no CSP" in names
    assert chains[0].severity == Severity.CRITICAL  # sorted most severe first


def test_cors_with_cookie_chain():
    findings = [
        _f("cors-misconfig", "CORS policy reflects arbitrary Origin"),
        _f("cookie-flags", "Cookie 'sid' set with insecure attributes"),
    ]
    chains = ChainBuilder().build(findings)
    assert any("CORS exposure" in c.name for c in chains)


def test_no_chain_when_unrelated():
    findings = [_f("security-headers", "Referrer-Policy header is missing")]
    assert ChainBuilder().build(findings) == []


def test_chain_requires_same_host():
    findings = [
        _f("reflected-xss", "Reflected input not HTML-encoded in parameter 'q'",
           "https://a.example.com/s?q=1"),
        _f("security-headers", "Content-Security-Policy header is missing",
           "https://b.example.com/"),
    ]
    assert ChainBuilder().build(findings) == []
