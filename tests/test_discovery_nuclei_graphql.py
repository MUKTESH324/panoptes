"""Content/param discovery, nuclei parsing, GraphQL plugin, session re-auth."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from conftest import FakeClient, make_response

from panoptes.config import CrawlConfig
from panoptes.crawler import Crawler
from panoptes.discovery import discover_content, discover_params
from panoptes.nuclei import parse_nuclei_jsonl
from panoptes.plugins.base import ScanContext
from panoptes.plugins.graphql import GraphQL
from panoptes.scope import Scope

# -- content discovery -----------------------------------------------------

async def test_discover_content_finds_real_path_and_feeds_pages():
    def handler(url, kwargs):
        if url.endswith("/admin"):
            return make_response(url, status=200, text="Admin panel here")
        return make_response(url, status=404, text="Not Found")

    pages: dict = {}
    findings = await discover_content("https://example.com/", FakeClient(handler),
                                      pages, ["admin", "nope"], 400)
    assert any("/admin" in f.title for f in findings)
    assert "https://example.com/admin" in pages  # 200 added to scan surface


async def test_discover_content_filters_soft_404():
    # Everything (incl. the random baseline) returns 200 with identical body.
    def handler(url, kwargs):
        return make_response(url, status=200, text="same catch-all page")

    findings = await discover_content("https://example.com/", FakeClient(handler),
                                      {}, ["admin", "login"], 400)
    assert findings == []


async def test_discover_content_filters_path_echoing_catchall():
    def handler(url, kwargs):
        # 200 for everything, body echoes the path but is otherwise identical.
        path = urlsplit(url).path
        return make_response(url, status=200,
                             text=f"<h1>Page {path}</h1>" + " boilerplate content " * 20)

    findings = await discover_content("https://example.com/", FakeClient(handler),
                                      {}, ["admin", "login", "config"], 400)
    assert findings == []


async def test_discover_params_detects_reflected_param():
    def handler(url, kwargs):
        q = parse_qs(urlsplit(url).query)
        if "debug" in q:
            return make_response(url, text="debugging " + q["debug"][0])
        return make_response(url, text="home page")

    findings = await discover_params("https://example.com/", FakeClient(handler),
                                     ["debug", "other"], 120)
    assert any("debug" in f.title for f in findings)
    assert not any("other" in f.title for f in findings)


# -- nuclei parsing --------------------------------------------------------

def test_parse_nuclei_jsonl():
    sample = (
        '{"template-id":"tech","info":{"name":"Nginx","severity":"info","tags":["tech"]},'
        '"matched-at":"https://x/"}\n'
        '{"template-id":"cve-2021-1","info":{"name":"RCE","severity":"critical",'
        '"classification":{"cwe-id":["CWE-78"]},"reference":["https://nvd"]},'
        '"matched-at":"https://x/a"}\n'
        'garbage line\n'
    )
    findings = parse_nuclei_jsonl(sample)
    assert len(findings) == 2
    crit = [f for f in findings if f.severity.name == "CRITICAL"][0]
    assert crit.cwe == "CWE-78"
    assert "nuclei" in crit.tags
    assert crit.references == ["https://nvd"]


# -- GraphQL ---------------------------------------------------------------

async def _run_graphql(handler):
    ctx = ScanContext(url="https://example.com/", client=FakeClient(handler))
    await GraphQL().check(ctx)
    return ctx.findings


async def test_graphql_introspection_enabled():
    def handler(url, kwargs):
        if url.endswith("/graphql"):
            return make_response(url, headers={"content-type": "application/json"},
                                 text='{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
        return make_response(url, status=404, text="nope")

    findings = await _run_graphql(handler)
    assert any("introspection" in f.title.lower() for f in findings)
    assert findings[0].severity.name == "MEDIUM"


async def test_graphql_endpoint_without_introspection():
    def handler(url, kwargs):
        if url.endswith("/graphql"):
            return make_response(url, headers={"content-type": "application/json"},
                                 text='{"errors":[{"message":"must provide query"}]}')
        return make_response(url, status=404, text="nope")

    findings = await _run_graphql(handler)
    assert any("endpoint exposed" in f.title.lower() for f in findings)


async def test_graphql_none_found():
    def handler(url, kwargs):
        return make_response(url, status=404, text="not found")

    assert await _run_graphql(handler) == []


# -- session re-auth -------------------------------------------------------

async def test_crawler_reauths_on_logout():
    logged_in = {"v": False}

    def handler(url, kwargs):
        text = "Welcome to your dashboard" if logged_in["v"] else "Please Sign in"
        return make_response(url, headers={"content-type": "text/html"}, text=text)

    async def relogin():
        logged_in["v"] = True

    crawler = Crawler(
        FakeClient(handler), Scope(allow=["example.com"], authorized=True),
        CrawlConfig(max_depth=0), relogin=relogin, logged_out_marker="Sign in",
    )
    results = await crawler.crawl("https://example.com/")
    assert crawler.reauth_count == 1
    assert "Welcome" in results["https://example.com/"].text


async def test_crawler_reauth_is_capped_when_login_stays_broken():
    def handler(url, kwargs):
        return make_response(url, headers={"content-type": "text/html"}, text="Please Sign in")

    async def relogin():
        pass  # never actually restores the session

    c = Crawler(
        FakeClient(handler), Scope(allow=["example.com"], authorized=True),
        CrawlConfig(max_depth=0), relogin=relogin, logged_out_marker="Sign in",
    )
    r = make_response("https://example.com/", headers={"content-type": "text/html"},
                      text="Please Sign in")
    for _ in range(6):
        await c._maybe_reauth("https://example.com/", r)
    assert c.reauth_count == c.max_reauth == 3
