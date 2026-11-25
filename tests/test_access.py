"""Access-control / IDOR checks."""

from __future__ import annotations

from conftest import FakeClient, make_response

from panoptes.access import find_idor, find_missing_auth

_LONG = "Your private account balance is 100 " * 10


async def test_missing_auth_flagged_when_anon_sees_same_page():
    url = "https://example.com/account"
    authed = {url: make_response(url, text=_LONG)}

    def handler(u, kwargs):
        return make_response(u, text=_LONG)  # anonymous gets the same page

    findings = await find_missing_auth(authed, FakeClient(handler))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-306"


async def test_missing_auth_not_flagged_when_login_required():
    url = "https://example.com/account"
    authed = {url: make_response(url, text=_LONG)}

    def handler(u, kwargs):
        return make_response(u, status=302, headers={"location": "/login"}, text="")

    assert await find_missing_auth(authed, FakeClient(handler)) == []


async def test_missing_auth_ignores_non_sensitive_paths():
    url = "https://example.com/about"
    authed = {url: make_response(url, text=_LONG)}

    def handler(u, kwargs):
        return make_response(u, text=_LONG)

    assert await find_missing_auth(authed, FakeClient(handler)) == []


async def test_idor_flagged_when_second_user_reads_object():
    url = "https://example.com/invoice?id=1"
    authed = {url: make_response(url, text="Invoice #1 total 500 " * 10)}

    def handler(u, kwargs):
        return make_response(u, text="Invoice #1 total 500 " * 10)  # user B sees it too

    findings = await find_idor(authed, FakeClient(handler))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-639"


async def test_idor_flagged_on_numeric_path_segment():
    url = "https://example.com/orders/1042"
    authed = {url: make_response(url, text="Order 1042 details " * 10)}

    def handler(u, kwargs):
        return make_response(u, text="Order 1042 details " * 10)

    assert len(await find_idor(authed, FakeClient(handler))) == 1


async def test_missing_auth_not_flagged_on_empty_bodies():
    url = "https://example.com/account"
    authed = {url: make_response(url, text="")}

    def handler(u, kwargs):
        return make_response(u, text="")  # both empty -> not enough to judge

    assert await find_missing_auth(authed, FakeClient(handler)) == []


async def test_idor_ignores_urls_without_object_ref():
    url = "https://example.com/home"
    authed = {url: make_response(url, text="homepage " * 10)}

    def handler(u, kwargs):
        return make_response(u, text="homepage " * 10)

    assert await find_idor(authed, FakeClient(handler)) == []
