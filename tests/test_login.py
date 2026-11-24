"""Login macro: form parsing, perform_login, and an end-to-end hunt login."""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import FakeClient, make_response

from panoptes.config import Config, LoginConfig
from panoptes.hunt import Hunt
from panoptes.login import parse_login_form, perform_login
from panoptes.scope import Scope

_LOGIN_HTML = (
    '<form action="/auth" method="post">'
    '<input type="hidden" name="csrf" value="tok123">'
    '<input type="text" name="user">'
    '<input type="password" name="pw"></form>'
)


def test_parse_login_form():
    form = parse_login_form(_LOGIN_HTML)
    assert form is not None
    assert form.password_field == "pw"
    assert form.username_field == "user"
    assert form.hidden == {"csrf": "tok123"}
    assert form.action == "/auth"
    assert form.method == "post"


async def test_perform_login_success_carries_csrf():
    captured = {}

    def handler(url, kwargs):
        if "data" in kwargs:
            captured["data"] = kwargs["data"]
            return make_response(url, text="Welcome to your Dashboard — Logout")
        return make_response(url, text=_LOGIN_HTML)

    cfg = LoginConfig(url="https://example.com/login", username="alice",
                      password="s3cret", success_indicator="Logout")
    res = await perform_login(FakeClient(handler), cfg)
    assert res.ok and res.verified
    assert captured["data"]["user"] == "alice"
    assert captured["data"]["pw"] == "s3cret"
    assert captured["data"]["csrf"] == "tok123"  # hidden field carried over


async def test_perform_login_failure_detected():
    def handler(url, kwargs):
        if "data" in kwargs:
            return make_response(url, text="Invalid credentials. Please Sign in")
        return make_response(url, text=_LOGIN_HTML)

    cfg = LoginConfig(url="https://example.com/login", username="a", password="b",
                      logged_out_indicator="Sign in")
    res = await perform_login(FakeClient(handler), cfg)
    assert not res.ok


async def test_perform_login_defaults_ok_without_indicator():
    def handler(url, kwargs):
        if "data" in kwargs:
            return make_response(url, status=302, headers={"location": "/home"}, text="")
        return make_response(url, text=_LOGIN_HTML)

    cfg = LoginConfig(url="https://example.com/login", username="a", password="b")
    res = await perform_login(FakeClient(handler), cfg)
    assert res.ok and not res.verified


# -- end-to-end against a real server -------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        authed = "session=ok" in self.headers.get("Cookie", "")
        path = urlsplit(self.path).path
        if path == "/login":
            body = (
                '<form action="/login" method="post">'
                '<input type="hidden" name="csrf" value="abc">'
                '<input name="user"><input type="password" name="pw"></form>'
            ).encode()
        elif path == "/account":
            body = (b"Welcome, your balance is 100" if authed else b"Please Sign in")
        else:
            body = b"<a href='/account'>account</a> <a href='/login'>login</a>"
        self._send(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(n).decode())
        ok = (data.get("user") == ["alice"] and data.get("pw") == ["secret"]
              and data.get("csrf") == ["abc"])
        self.send_response(200)
        if ok:
            self.send_header("Set-Cookie", "session=ok; Path=/")
        self.send_header("Content-Type", "text/html")
        body = b"Logout" if ok else b"Sign in - invalid"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def login_server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_hunt_logs_in_end_to_end(login_server):
    cfg = Config()
    cfg.target = login_server + "/"
    cfg.http.requests_per_second = 100
    cfg.scope.allow = ["127.0.0.1"]
    cfg.scope.allow_private = True
    cfg.scope.authorized = True
    cfg.login.url = login_server + "/login"
    cfg.login.username = "alice"
    cfg.login.password = "secret"
    cfg.login.success_indicator = "Logout"

    scope = Scope(allow=["127.0.0.1"], allow_private=True, authorized=True)
    hunt = asyncio.run(Hunt(cfg, scope).run())
    assert hunt.meta.get("login") is True
