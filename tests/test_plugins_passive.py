from conftest import make_response

from argus.plugins.base import ScanContext
from argus.plugins.cookies import CookieFlags
from argus.plugins.info_disclosure import InfoDisclosure
from argus.plugins.security_headers import SecurityHeaders


async def _run(plugin, response):
    ctx = ScanContext(url=str(response.request.url), client=None, response=response)
    await plugin.check(ctx)
    return ctx.findings


async def test_security_headers_flags_missing():
    resp = make_response("https://example.com/", headers={})
    findings = await _run(SecurityHeaders(), resp)
    titles = " ".join(f.title for f in findings)
    assert "Content-Security-Policy" in titles
    assert "HSTS" in titles or "Strict Transport" in titles


async def test_security_headers_clean_when_present():
    resp = make_response(
        "https://example.com/",
        headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        },
    )
    findings = await _run(SecurityHeaders(), resp)
    assert findings == []


async def test_cookie_flags_detects_insecure():
    resp = make_response(
        "https://example.com/",
        set_cookies=["sid=abc; Path=/"],
    )
    findings = await _run(CookieFlags(), resp)
    assert len(findings) == 1
    assert "Secure" in findings[0].evidence
    assert "HttpOnly" in findings[0].evidence


async def test_cookie_flags_ok_when_hardened():
    resp = make_response(
        "https://example.com/",
        set_cookies=["sid=abc; Secure; HttpOnly; SameSite=Strict"],
    )
    findings = await _run(CookieFlags(), resp)
    assert findings == []


async def test_info_disclosure_version_and_trace():
    resp = make_response(
        "https://example.com/",
        headers={"server": "nginx/1.18.0"},
        text="Traceback (most recent call last): File ...",
    )
    findings = await _run(InfoDisclosure(), resp)
    titles = " ".join(f.title for f in findings)
    assert "version disclosed" in titles
    assert "stack trace" in titles.lower()
