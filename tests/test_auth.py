"""Authenticated-scan mode: config, client wiring, CLI parsing, end-to-end."""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from panoptes.cli import _load_config, build_parser
from panoptes.config import AuthConfig, Config
from panoptes.http_client import ScopedHttpClient
from panoptes.hunt import Hunt
from panoptes.scope import Scope

# -- config / parsing -----------------------------------------------------

def test_authconfig_active():
    assert not AuthConfig().active
    assert AuthConfig(cookies={"s": "1"}).active
    assert AuthConfig(headers={"Authorization": "Bearer x"}).active


def test_config_from_dict_auth():
    cfg = Config.from_dict({"auth": {"headers": {"X-Api": "k"}, "cookies": {"sid": "abc"}}})
    assert cfg.auth.headers == {"X-Api": "k"}
    assert cfg.auth.cookies == {"sid": "abc"}


def test_cli_parses_headers_and_cookies():
    args = build_parser().parse_args([
        "scan", "https://example.com", "--i-am-authorized",
        "-H", "Authorization: Bearer tok",
        "-b", "session=letmein; theme=dark",
    ])
    cfg = _load_config(args)
    assert cfg.auth.headers == {"Authorization": "Bearer tok"}
    assert cfg.auth.cookies == {"session": "letmein", "theme": "dark"}


def test_cli_ignores_malformed_header(capsys):
    args = build_parser().parse_args([
        "scan", "https://example.com", "--i-am-authorized", "-H", "no-colon-here",
    ])
    cfg = _load_config(args)
    assert cfg.auth.headers == {}
    assert "malformed" in capsys.readouterr().err


# -- client wiring --------------------------------------------------------

def test_scoped_client_attaches_auth():
    async def go():
        scope = Scope(allow=["example.com"], authorized=True)
        auth = AuthConfig(headers={"Authorization": "Bearer tok"}, cookies={"sid": "abc"})
        async with ScopedHttpClient(scope, auth=auth, cookie_domain="example.com") as c:
            assert c._client.headers["authorization"] == "Bearer tok"
            # cookie is bound to the target domain
            assert c._client.cookies.get("sid", domain="example.com") == "abc"

    asyncio.run(go())


# -- end-to-end behind-login ---------------------------------------------

class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        authed = "session=letmein" in self.headers.get("Cookie", "")
        path = urlsplit(self.path).path
        if not authed:
            body = b"<html><body><a href='/login'>Sign in</a></body></html>"
        elif path == "/account":
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html><body>Hello {q}</body></html>".encode()
        else:
            body = b"<html><body><a href='/account?q=hi'>account</a></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def auth_server():
    httpd = HTTPServer(("127.0.0.1", 0), _AuthHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _cfg(target, cookies=None):
    cfg = Config()
    cfg.target = target
    cfg.http.requests_per_second = 100
    cfg.scope.allow = ["127.0.0.1"]
    cfg.scope.allow_private = True
    cfg.scope.authorized = True
    if cookies:
        cfg.auth.cookies = cookies
    return cfg


def _scope():
    return Scope(allow=["127.0.0.1"], allow_private=True, authorized=True)


def test_authenticated_scan_reaches_protected_area(auth_server):
    hunt = asyncio.run(Hunt(_cfg(auth_server, cookies={"session": "letmein"}), _scope()).run())
    titles = " ".join(f.title for f in hunt.findings)
    assert hunt.meta.get("authenticated") is True
    # The reflected-XSS on /account is only reachable once logged in.
    assert "Reflected input not HTML-encoded" in titles


def test_unauthenticated_scan_cannot_reach_protected_area(auth_server):
    hunt = asyncio.run(Hunt(_cfg(auth_server), _scope()).run())
    titles = " ".join(f.title for f in hunt.findings)
    assert "Reflected input not HTML-encoded" not in titles
