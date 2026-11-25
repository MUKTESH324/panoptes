"""Method-tampering and privilege-parameter checks (horizontal priv-esc)."""

from __future__ import annotations

from conftest import make_response

from panoptes.plugins.base import ScanContext
from panoptes.plugins.method_tampering import MethodTampering
from panoptes.plugins.privilege_params import PrivilegeParams


class _MethodClient:
    """Client that passes the HTTP method through to the handler."""

    def __init__(self, handler):
        self.handler = handler

    async def request(self, method, url, **kwargs):
        return self.handler(method, url, kwargs)

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)


# -- method tampering ------------------------------------------------------

async def test_method_tampering_bypass_via_override_header():
    def handler(method, url, kwargs):
        if "X-HTTP-Method-Override" in kwargs.get("headers", {}):
            return make_response(url, status=200, text="admin panel contents")
        return make_response(url, status=403, text="forbidden")

    resp = make_response("https://example.com/admin", status=403, text="forbidden")
    ctx = ScanContext(url="https://example.com/admin", client=_MethodClient(handler), response=resp)
    await MethodTampering().check(ctx)
    assert any(f.cwe == "CWE-650" for f in ctx.findings)


async def test_method_tampering_no_bypass():
    def handler(method, url, kwargs):
        return make_response(url, status=403, text="forbidden")

    resp = make_response("https://example.com/admin", status=403, text="forbidden")
    ctx = ScanContext(url="https://example.com/admin", client=_MethodClient(handler), response=resp)
    await MethodTampering().check(ctx)
    assert ctx.findings == []


async def test_method_tampering_skips_allowed_endpoints():
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        return make_response(url, status=200, text="x")

    resp = make_response("https://example.com/", status=200, text="ok")
    ctx = ScanContext(url="https://example.com/", client=_MethodClient(handler), response=resp)
    await MethodTampering().check(ctx)
    assert ctx.findings == [] and calls["n"] == 0  # no probing on an allowed endpoint


# -- privilege parameters --------------------------------------------------

async def _run_pp(url, response):
    ctx = ScanContext(url=url, client=None, response=response)
    await PrivilegeParams().check(ctx)
    return ctx.findings


async def test_privilege_param_in_query():
    url = "https://example.com/x?is_admin=0&foo=1"
    findings = await _run_pp(url, make_response(url, text="ok"))
    assert any("is_admin" in f.title for f in findings)
    assert any(f.cwe == "CWE-639" for f in findings)


async def test_privilege_param_hidden_form_field():
    html = ('<form method="post"><input type="hidden" name="role" value="user">'
            '<input name="q"></form>')
    resp = make_response("https://example.com/", headers={"content-type": "text/html"}, text=html)
    findings = await _run_pp("https://example.com/", resp)
    assert any("role" in f.title for f in findings)
    assert any(f.cwe == "CWE-915" for f in findings)


async def test_privilege_param_none():
    url = "https://example.com/x?q=hello"
    resp = make_response(url, headers={"content-type": "text/html"}, text="<p>no forms</p>")
    assert await _run_pp(url, resp) == []
