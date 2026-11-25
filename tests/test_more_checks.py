"""XXE, deserialization, WebSocket, GraphQL-abuse, auth rate-limit."""

from __future__ import annotations

from conftest import FakeClient, make_response

from panoptes.authratelimit import check_auth_rate_limit
from panoptes.config import LoginConfig
from panoptes.plugins.base import ScanContext
from panoptes.plugins.deserialization import Deserialization
from panoptes.plugins.graphql import GraphQL
from panoptes.plugins.websocket import WebSocketCheck
from panoptes.plugins.xxe import Xxe

# -- XXE -------------------------------------------------------------------

async def test_xxe_detected():
    def handler(url, kwargs):
        if "content" in kwargs:  # the XML probe was posted
            return make_response(url, text="root:x:0:0:root:/root:/bin/bash\n")
        return make_response(url, text="ok")

    ctx = ScanContext(url="https://example.com/api", client=FakeClient(handler))
    await Xxe().check(ctx)
    assert any(f.cwe == "CWE-611" for f in ctx.findings)


async def test_xxe_no_false_positive():
    def handler(url, kwargs):
        return make_response(url, text="no entities parsed here")

    ctx = ScanContext(url="https://example.com/api", client=FakeClient(handler))
    await Xxe().check(ctx)
    assert ctx.findings == []


# -- Deserialization -------------------------------------------------------

async def _run_deser(url, response):
    ctx = ScanContext(url=url, client=None, response=response)
    await Deserialization().check(ctx)
    return ctx.findings


async def test_deser_java_cookie():
    resp = make_response("https://example.com/", set_cookies=["s=rO0ABXNyABFqYXZh; Path=/"])
    findings = await _run_deser("https://example.com/", resp)
    assert any(f.cwe == "CWE-502" for f in findings)


async def test_deser_php_param():
    url = 'https://example.com/?data=O:4:"User":1:{s:4:"name";s:3:"bob";}'
    findings = await _run_deser(url, make_response(url, text="ok"))
    assert any(f.cwe == "CWE-502" for f in findings)


async def test_deser_none():
    resp = make_response("https://example.com/", set_cookies=["s=abc123; Path=/"])
    assert await _run_deser("https://example.com/", resp) == []


# -- WebSocket -------------------------------------------------------------

async def _run_ws(html):
    resp = make_response("https://example.com/", headers={"content-type": "text/html"}, text=html)
    ctx = ScanContext(url="https://example.com/", client=None, response=resp)
    await WebSocketCheck().check(ctx)
    return ctx.findings


async def test_ws_cleartext_flagged():
    findings = await _run_ws('<script>var s=new WebSocket("ws://example.com/sock");</script>')
    assert any(f.cwe == "CWE-319" for f in findings)


async def test_ws_secure_is_info():
    findings = await _run_ws('<script>new WebSocket("wss://example.com/s");</script>')
    assert len(findings) == 1 and findings[0].severity.name == "INFO"


async def test_ws_none():
    assert await _run_ws("<p>no sockets</p>") == []


# -- GraphQL abuse ---------------------------------------------------------

async def test_graphql_abuse_suggestions_and_batching():
    def handler(url, kwargs):
        if not url.endswith("/graphql"):
            return make_response(url, status=404, text="no")
        body = kwargs.get("json")
        if isinstance(body, list):
            return make_response(url, headers={"content-type": "application/json"},
                                 text='[{"data":{}},{"data":{}}]')
        q = body.get("query", "") if isinstance(body, dict) else ""
        if "__schema" in q:
            return make_response(url, headers={"content-type": "application/json"},
                                 text='{"data":{"__schema":{"types":[{"name":"Q"}]}}}')
        if "panoptes_nope" in q:
            return make_response(url, text='{"errors":[{"message":"Did you mean \\"name\\"?"}]}')
        return make_response(url, text='{"data":{}}')

    ctx = ScanContext(url="https://example.com/", client=FakeClient(handler))
    await GraphQL().check(ctx)
    titles = " ".join(f.title.lower() for f in ctx.findings)
    assert "introspection" in titles
    assert "suggestion" in titles
    assert "batching" in titles


# -- Auth rate-limit -------------------------------------------------------

_LOGIN_FORM = ('<form action="/login" method="post">'
               '<input name="username"><input type="password" name="password"></form>')


async def test_auth_ratelimit_flagged_when_unthrottled():
    def handler(url, kwargs):
        if "data" in kwargs:
            return make_response(url, status=200, text="invalid credentials")
        return make_response(url, text=_LOGIN_FORM)

    cfg = LoginConfig(url="https://example.com/login")
    findings = await check_auth_rate_limit(cfg, FakeClient(handler), attempts=5)
    assert len(findings) == 1 and findings[0].cwe == "CWE-307"


async def test_auth_ratelimit_respected_on_429():
    state = {"n": 0}

    def handler(url, kwargs):
        if "data" in kwargs:
            state["n"] += 1
            if state["n"] >= 3:
                return make_response(url, status=429, text="too many requests")
            return make_response(url, status=200, text="invalid")
        return make_response(url, text=_LOGIN_FORM)

    cfg = LoginConfig(url="https://example.com/login")
    findings = await check_auth_rate_limit(cfg, FakeClient(handler), attempts=10)
    assert findings == []
