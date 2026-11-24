"""SSRF probe plugin."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from conftest import FakeClient, make_response

from panoptes.plugins.base import ScanContext
from panoptes.plugins.ssrf import SsrfProbe


def _injected_host(url: str, param: str) -> str:
    val = parse_qs(urlsplit(url).query).get(param, [""])[0]
    return urlsplit(val).hostname or ""


async def _run(url, handler, response=None):
    ctx = ScanContext(url=url, client=FakeClient(handler), response=response)
    await SsrfProbe().check(ctx)
    return ctx.findings


async def test_ssrf_firm_when_canary_host_in_fetch_error():
    def handler(url, kwargs):
        host = _injected_host(url, "url")
        return make_response(url, text=f"cURL error (6): Could not resolve host: {host}")

    findings = await _run("https://example.com/fetch?url=http://a.test/", handler)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-918"
    assert str(findings[0].confidence) == "firm"


async def test_ssrf_tentative_on_generic_fetch_error():
    def handler(url, kwargs):
        return make_response(url, text="Warning: connection refused")

    findings = await _run("https://example.com/fetch?url=http://a.test/", handler)
    assert len(findings) == 1
    assert str(findings[0].confidence) == "tentative"


async def test_ssrf_detects_url_valued_param_by_value():
    def handler(url, kwargs):
        host = _injected_host(url, "foo")
        return make_response(url, text=f"getaddrinfo failed for {host}")

    findings = await _run("https://example.com/p?foo=http://a.example/", handler)
    assert any(f.plugin == "ssrf" for f in findings)


async def test_ssrf_no_finding_on_benign_response():
    def handler(url, kwargs):
        return make_response(url, text="here are your results")

    findings = await _run("https://example.com/fetch?url=http://a.test/", handler)
    assert findings == []


async def test_ssrf_ignores_non_url_params():
    def handler(url, kwargs):
        return make_response(url, text="could not resolve host whatever")

    findings = await _run("https://example.com/search?q=hello", handler)
    assert findings == []


async def test_ssrf_oob_probe_when_canary_set(monkeypatch):
    monkeypatch.setenv("PANOPTES_SSRF_CANARY", "oob.example")

    def handler(url, kwargs):
        return make_response(url, text="ok")  # no in-band signal

    findings = await _run("https://example.com/fetch?url=http://a.test/", handler)
    assert any("out-of-band" in f.title.lower() for f in findings)
    assert all(f.plugin == "ssrf" for f in findings)
