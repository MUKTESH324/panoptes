from conftest import FakeClient, make_response

from argus.plugins.base import ScanContext
from argus.plugins.cors import CorsMisconfig
from argus.plugins.open_redirect import OpenRedirect
from argus.plugins.reflected_xss import ReflectedXSS
from argus.plugins.sqli_error import SqliError


async def test_cors_reflects_origin():
    def handler(url, kwargs):
        origin = kwargs.get("headers", {}).get("Origin", "")
        return make_response(
            url,
            headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
        )

    ctx = ScanContext(url="https://example.com/api", client=FakeClient(handler))
    await CorsMisconfig().check(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].severity.name == "HIGH"


async def test_cors_safe_when_not_reflected():
    def handler(url, kwargs):
        return make_response(url, headers={"access-control-allow-origin": "https://trusted.example"})

    ctx = ScanContext(url="https://example.com/api", client=FakeClient(handler))
    await CorsMisconfig().check(ctx)
    assert ctx.findings == []


async def test_reflected_xss_detects_unencoded():
    captured = {}

    def handler(url, kwargs):
        # Echo the injected payload verbatim into an HTML body.
        payload = url.split("q=")[-1]
        from urllib.parse import unquote

        captured["payload"] = unquote(payload)
        return make_response(url, headers={"content-type": "text/html"},
                             text=f"<div>{unquote(payload)}</div>")

    ctx = ScanContext(url="https://example.com/s?q=hi", client=FakeClient(handler))
    await ReflectedXSS().check(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].cwe == "CWE-79"


async def test_reflected_xss_safe_when_encoded():
    def handler(url, kwargs):
        return make_response(url, headers={"content-type": "text/html"},
                             text="<div>&lt;argus&gt;</div>")

    ctx = ScanContext(url="https://example.com/s?q=hi", client=FakeClient(handler))
    await ReflectedXSS().check(ctx)
    assert ctx.findings == []


async def test_sqli_error_detected():
    def handler(url, kwargs):
        return make_response(url, text="You have an error in your SQL syntax near ''")

    ctx = ScanContext(url="https://example.com/i?id=1", client=FakeClient(handler),
                      response=make_response("https://example.com/i?id=1", text="ok"))
    await SqliError().check(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].cwe == "CWE-89"


async def test_open_redirect_detected():
    def handler(url, kwargs):
        return make_response(url, status=302,
                             headers={"location": "https://argus-redirect-probe.example/"})

    ctx = ScanContext(url="https://example.com/go?next=/home", client=FakeClient(handler))
    await OpenRedirect().check(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].cwe == "CWE-601"


async def test_open_redirect_skipped_without_redirect_param():
    ctx = ScanContext(url="https://example.com/go?q=1", client=FakeClient(lambda u, k: make_response(u)))
    await OpenRedirect().check(ctx)
    assert ctx.findings == []
