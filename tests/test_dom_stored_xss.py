"""DOM-XSS plugin, stored-XSS pass, form parser, and browser-crawler fallback."""

from __future__ import annotations

from conftest import FakeClient, make_response

from panoptes.browser_crawler import BrowserCrawler
from panoptes.plugins.base import ScanContext
from panoptes.plugins.dom_xss import DomXss
from panoptes.scope import Scope
from panoptes.stored_xss import find_stored_xss
from panoptes.utils.forms import parse_forms

# -- DOM XSS ---------------------------------------------------------------

async def _run_dom(html, ctype="text/html"):
    resp = make_response("https://example.com/", headers={"content-type": ctype}, text=html)
    ctx = ScanContext(url="https://example.com/", client=None, response=resp)
    await DomXss().check(ctx)
    return ctx.findings


async def test_dom_xss_source_and_sink():
    html = '<script>var x = location.hash; document.getElementById("o").innerHTML = x;</script>'
    findings = await _run_dom(html)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"


async def test_dom_xss_source_only_no_finding():
    assert await _run_dom("<script>var x = location.hash;</script>") == []


async def test_dom_xss_sink_only_no_finding():
    assert await _run_dom('<script>el.innerHTML = "static string";</script>') == []


async def test_dom_xss_ignores_non_html():
    html = '<script>location.hash; el.innerHTML=1</script>'
    assert await _run_dom(html, ctype="application/json") == []


# -- Form parser -----------------------------------------------------------

def test_parse_forms():
    html = ('<form action="/c" method="post">'
            '<input type="hidden" name="t" value="1">'
            '<textarea name="body"></textarea><input name="q"></form>')
    forms = parse_forms(html)
    assert len(forms) == 1
    assert forms[0].action == "/c" and forms[0].method == "post"
    assert forms[0].hidden == {"t": "1"}
    assert "body" in forms[0].text_fields and "q" in forms[0].text_fields


# -- Stored XSS ------------------------------------------------------------

_FORM = '<form method="post" action=""><textarea name="comment"></textarea></form>'


def _stored_server(encode: bool):
    store = {"val": ""}

    def handler(url, kwargs):
        if "data" in kwargs:  # POST: "save" the comment
            for v in kwargs["data"].values():
                if v.startswith("<panostored"):
                    store["val"] = v
            return make_response(url, headers={"content-type": "text/html"}, text="saved")
        shown = store["val"]
        if encode:
            shown = shown.replace("<", "&lt;").replace(">", "&gt;")
        body = _FORM + "<div class=comment>" + shown + "</div>"
        return make_response(url, headers={"content-type": "text/html"}, text=body)

    return handler


async def test_stored_xss_detected_when_persisted_unencoded():
    init = make_response("https://example.com/guestbook",
                         headers={"content-type": "text/html"}, text=_FORM)
    pages = {"https://example.com/guestbook": init}
    findings = await find_stored_xss(pages, FakeClient(_stored_server(encode=False)))
    assert len(findings) == 1
    assert findings[0].plugin == "stored-xss"
    assert findings[0].cwe == "CWE-79"


async def test_stored_xss_not_detected_when_encoded():
    init = make_response("https://example.com/guestbook",
                         headers={"content-type": "text/html"}, text=_FORM)
    pages = {"https://example.com/guestbook": init}
    findings = await find_stored_xss(pages, FakeClient(_stored_server(encode=True)))
    assert findings == []


async def test_stored_xss_no_forms_no_submission():
    init = make_response("https://example.com/", headers={"content-type": "text/html"},
                         text="<p>no forms here</p>")
    findings = await find_stored_xss({"https://example.com/": init},
                                     FakeClient(lambda u, k: make_response(u, text="x")))
    assert findings == []


# -- Browser crawler fallback ---------------------------------------------

def test_browser_crawler_available_is_bool():
    assert isinstance(BrowserCrawler.available(), bool)


async def test_browser_crawler_discover_degrades_gracefully():
    bc = BrowserCrawler(Scope(allow=["example.com"], authorized=True))
    if BrowserCrawler.available():
        return  # a real browser is installed; skip the fallback assertion
    found, errs = await bc.discover("https://example.com/")
    assert found == set()
    assert errs and "Playwright" in errs[0]
