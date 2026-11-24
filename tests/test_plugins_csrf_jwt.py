"""CSRF and JWT passive plugins."""

from __future__ import annotations

import base64
import json

from conftest import make_response

from panoptes.plugins.base import ScanContext
from panoptes.plugins.csrf import CsrfForms
from panoptes.plugins.jwt import JwtChecks


async def _run(plugin, url, response):
    ctx = ScanContext(url=url, client=None, response=response)
    await plugin.check(ctx)
    return ctx.findings


def _jwt(header: dict, payload: dict) -> str:
    def seg(d):
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{seg(header)}.{seg(payload)}.sig"


# -- CSRF -----------------------------------------------------------------

async def test_csrf_flags_post_form_without_token():
    html = '<html><body><form method="post" action="/transfer">' \
           '<input name="amount"></form></body></html>'
    resp = make_response("https://example.com/pay", headers={"content-type": "text/html"}, text=html)
    findings = await _run(CsrfForms(), "https://example.com/pay", resp)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-352"


async def test_csrf_ok_when_token_present():
    html = '<form method="post" action="/x">' \
           '<input type="hidden" name="csrf_token" value="abc"><input name="q"></form>'
    resp = make_response("https://example.com/", headers={"content-type": "text/html"}, text=html)
    assert await _run(CsrfForms(), "https://example.com/", resp) == []


async def test_csrf_ignores_get_forms():
    html = '<form method="get" action="/search"><input name="q"></form>'
    resp = make_response("https://example.com/", headers={"content-type": "text/html"}, text=html)
    assert await _run(CsrfForms(), "https://example.com/", resp) == []


# -- JWT ------------------------------------------------------------------

async def test_jwt_alg_none_high():
    token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    resp = make_response("https://example.com/", set_cookies=[f"session={token}; Path=/"])
    findings = await _run(JwtChecks(), "https://example.com/", resp)
    titles = [f.title for f in findings]
    assert any("none" in t for t in titles)
    assert any(f.severity.name == "HIGH" for f in findings)


async def test_jwt_no_exp_low():
    token = _jwt({"alg": "HS256"}, {"sub": "1", "role": "user"})
    resp = make_response("https://example.com/", text=f"token: {token}")
    findings = await _run(JwtChecks(), "https://example.com/", resp)
    assert any("expiration" in f.title for f in findings)


async def test_jwt_in_url_medium():
    token = _jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999})
    url = f"https://example.com/cb?token={token}"
    resp = make_response(url, text="ok")
    findings = await _run(JwtChecks(), url, resp)
    assert any("URL" in f.title for f in findings)


async def test_jwt_sensitive_claim_low():
    token = _jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999, "password": "x"})
    resp = make_response("https://example.com/", text=token)
    findings = await _run(JwtChecks(), "https://example.com/", resp)
    assert any("sensitive" in f.title.lower() for f in findings)


async def test_jwt_ignores_non_jwt():
    resp = make_response("https://example.com/", text="just some eyJ text that is not a token")
    assert await _run(JwtChecks(), "https://example.com/", resp) == []
