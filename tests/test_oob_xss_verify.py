"""OOB listener, SSRF-OOB confirmation, and browser XSS verifier (mocked)."""

from __future__ import annotations

import time
import urllib.request
from urllib.parse import parse_qs, urlsplit

from conftest import FakeClient, make_response

from panoptes.oob import OobListener
from panoptes.ssrf_oob import run_ssrf_oob
from panoptes.xss_verify import XssVerifier, verify_reflected, verify_stored

# -- OOB listener ----------------------------------------------------------

def test_oob_listener_records_hits():
    with OobListener(bind_host="127.0.0.1") as listener:
        token = "abc123def"
        urllib.request.urlopen(listener.base_url + "/" + token, timeout=3).read()
        time.sleep(0.1)
        assert token in listener.tokens_hit()


async def test_ssrf_oob_confirms_blind_ssrf():
    listener = OobListener(bind_host="127.0.0.1").start()

    def handler(url, kwargs):
        # Simulate the target performing a server-side fetch of the injected URL.
        for vals in parse_qs(urlsplit(url).query).values():
            for v in vals:
                if listener.base_url in v:
                    try:
                        urllib.request.urlopen(v, timeout=3).read()
                    except Exception:  # noqa: BLE001
                        pass
        return make_response(url, text="ok")

    url = "https://example.com/fetch?url=http://a.test/"
    pages = {url: make_response(url, text="ok")}
    try:
        findings = await run_ssrf_oob(pages, FakeClient(handler), listener, grace=0.5)
    finally:
        listener.stop()
    assert any(f.cwe == "CWE-918" and str(f.confidence) == "certain" for f in findings)


async def test_ssrf_oob_no_finding_without_callback():
    listener = OobListener(bind_host="127.0.0.1").start()

    def handler(url, kwargs):
        return make_response(url, text="ok")  # server never fetches the URL

    url = "https://example.com/fetch?url=http://a.test/"
    try:
        findings = await run_ssrf_oob({url: make_response(url)}, FakeClient(handler),
                                      listener, grace=0.3)
    finally:
        listener.stop()
    assert findings == []


# -- Browser XSS verifier (mocked) -----------------------------------------

class _FakeVerifier:
    """Pretends the given parameter is the one whose payload executes."""

    def __init__(self, vulnerable_param: str) -> None:
        self.p = vulnerable_param

    async def executes(self, url: str) -> bool:
        vals = parse_qs(urlsplit(url).query).get(self.p, [])
        return any("window.__panoptes_xss=1" in v for v in vals)


async def test_verify_reflected_confirms_vulnerable_param():
    findings = await verify_reflected(["https://example.com/s?q=hi&x=1"], _FakeVerifier("q"))
    assert len(findings) == 1
    assert str(findings[0].confidence) == "certain"
    assert "q" in findings[0].title


async def test_verify_reflected_none_when_not_vulnerable():
    findings = await verify_reflected(["https://example.com/s?q=hi"], _FakeVerifier("zzz"))
    assert findings == []


async def test_verify_stored_confirms_execution():
    class StoredFake:
        async def executes(self, url: str) -> bool:
            return url.endswith("/guestbook")

    form = '<form method="post" action=""><textarea name="c"></textarea></form>'
    pages = {"https://example.com/guestbook": make_response(
        "https://example.com/guestbook", headers={"content-type": "text/html"}, text=form)}
    findings = await verify_stored(pages, StoredFake(),
                                   FakeClient(lambda u, k: make_response(u, text="ok")))
    assert len(findings) == 1
    assert findings[0].plugin == "xss-verified"


def test_xss_verifier_available_is_bool():
    assert isinstance(XssVerifier.available(), bool)
