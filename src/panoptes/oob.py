"""Bundled out-of-band (OOB) interaction listener.

A small threaded HTTP server that records any request it receives, keyed by a
token in the path. Panoptes injects URLs pointing at this listener into the
target; if the *server* fetches one (blind SSRF, blind XXE, some RCE), the
listener records the token and the interaction is confirmed.

Reachability: the target must be able to reach the listener's address. For a
local/internal target the default 127.0.0.1 works; for an external target, run
Panoptes on a host the target can reach and pass ``--oob-host <public-addr>``
(the address to advertise) while the server binds locally.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional


@dataclass
class Interaction:
    token: str
    at: float
    source: str
    path: str


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _record(self):
        token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
        if token:
            self.server.record(token, self.client_address[0], self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        try:
            self.wfile.write(b"ok")
        except Exception:  # noqa: BLE001
            pass

    do_GET = _record
    do_POST = _record


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self._interactions: List[Interaction] = []
        self._lock = threading.Lock()

    def record(self, token: str, source: str, path: str) -> None:
        with self._lock:
            self._interactions.append(Interaction(token, time.time(), source, path))

    def snapshot(self) -> List[Interaction]:
        with self._lock:
            return list(self._interactions)


@dataclass
class OobListener:
    bind_host: str = "127.0.0.1"
    advertise_host: Optional[str] = None
    port: int = 0
    _server: Optional[_Server] = field(default=None, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)

    def start(self) -> "OobListener":
        self._server = _Server((self.bind_host, self.port), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def base_url(self) -> str:
        host = self.advertise_host or self.bind_host
        return f"http://{host}:{self.port}"

    def interactions(self) -> List[Interaction]:
        return self._server.snapshot() if self._server else []

    def tokens_hit(self) -> set:
        return {i.token for i in self.interactions()}

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    def __enter__(self) -> "OobListener":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
