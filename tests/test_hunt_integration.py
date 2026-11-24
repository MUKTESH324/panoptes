"""End-to-end hunt against a local, deliberately-insecure server (127.0.0.1)."""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from argus.brain import Brain
from argus.config import Config
from argus.hunt import Hunt
from argus.reporting.hunt import render_hunt
from argus.scope import Scope


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            body = f"<html><body>Results for {q}</body></html>".encode()
        else:
            body = (
                b"<html><body><h1>home</h1>"
                b"<a href='/search?q=test'>search</a></body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.send_header("Server", "TestServer/1.2.3")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _config(target: str) -> Config:
    cfg = Config()
    cfg.target = target
    cfg.http.requests_per_second = 100
    cfg.scope.allow = ["127.0.0.1"]
    cfg.scope.allow_private = True
    cfg.scope.authorized = True
    return cfg


def _scope() -> Scope:
    return Scope(allow=["127.0.0.1"], allow_private=True, authorized=True)


def test_hunt_full_pipeline(server):
    cfg = _config(server)
    brain = Brain(":memory:")
    hunt = asyncio.run(Hunt(cfg, _scope(), brain=brain).run())

    # Planner produced phases.
    assert hunt.plan is not None
    assert hunt.plan.phases[0].name == "recon"

    # Found the reflected XSS and header issues.
    titles = " ".join(f.title for f in hunt.findings)
    assert "Reflected input not HTML-encoded" in titles

    # Validation ran and kept the strong XSS finding.
    assert hunt.validation is not None
    assert hunt.validation.summary()["confirmed"] >= 1

    # Exploit chain inferred (XSS + missing CSP => critical).
    assert any("XSS" in c.name for c in hunt.chains)

    # Brain diff: first run => everything new.
    assert hunt.diff is not None
    assert len(hunt.diff.new) == len(hunt.findings)

    # Report renders.
    md = render_hunt(hunt, "markdown")
    assert "Argus hunt report" in md
    assert "Exploit chains" in md
    brain.close()


def test_hunt_second_run_diff(server):
    cfg = _config(server)
    brain = Brain(":memory:")
    asyncio.run(Hunt(cfg, _scope(), brain=brain).run())
    hunt2 = asyncio.run(Hunt(cfg, _scope(), brain=brain).run())
    # Second run: nothing new, everything known.
    assert hunt2.diff is not None
    assert len(hunt2.diff.new) == 0
    assert len(hunt2.diff.known) == len(hunt2.findings)
    brain.close()
