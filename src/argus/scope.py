"""Scope enforcement and authorization gate.

This is the safety core of Argus. No request is ever issued to a host that is
not explicitly in scope, and a scan cannot start unless the operator has
affirmed they are authorized to test the target.

Scope rules:
  * An allowlist of hosts (exact or wildcard, e.g. ``*.example.com``) defines
    what may be scanned.
  * A denylist always wins over the allowlist.
  * Private / loopback / link-local addresses are blocked by default to avoid
    accidental SSRF-style pivoting onto internal infrastructure, unless the
    operator opts in with ``allow_private``.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable, List
from urllib.parse import urlsplit

from .models import Target


class AuthorizationError(RuntimeError):
    """Raised when a scan is attempted without affirmed authorization."""


class OutOfScopeError(RuntimeError):
    """Raised when a URL falls outside the configured scope."""


@dataclass
class Scope:
    """Defines and enforces what Argus is permitted to touch."""

    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    allow_private: bool = False
    authorized: bool = False

    def require_authorization(self) -> None:
        """Hard gate — call before a scan begins."""
        if not self.authorized:
            raise AuthorizationError(
                "Scan refused: authorization not affirmed. You must confirm you "
                "have explicit written permission to test the target "
                "(set authorized=True / pass --i-am-authorized)."
            )
        if not self.allow:
            raise AuthorizationError(
                "Scan refused: empty scope allowlist. Add at least one host to "
                "'allow' so Argus knows exactly what it may touch."
            )

    def host_allowed(self, host: str) -> bool:
        host = host.lower().strip("[]")
        if any(fnmatch.fnmatch(host, pat.lower()) for pat in self.deny):
            return False
        return any(fnmatch.fnmatch(host, pat.lower()) for pat in self.allow)

    def is_private_host(self, host: str) -> bool:
        """Resolve host and return True if it maps to a non-public address."""
        host = host.strip("[]")
        addrs: List[str] = []
        try:
            ip = ipaddress.ip_address(host)
            addrs = [str(ip)]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
                addrs = [str(info[4][0]) for info in infos]
            except socket.gaierror:
                # Can't resolve — treat as private to fail safe.
                return True
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                return True
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return True
        return False

    def check_url(self, url: str) -> Target:
        """Validate a URL against scope, returning a normalized Target.

        Raises OutOfScopeError if the URL may not be scanned.
        """
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise OutOfScopeError(f"unsupported scheme: {url!r}")
        host = parts.hostname
        if not host:
            raise OutOfScopeError(f"no host in url: {url!r}")
        if not self.host_allowed(host):
            raise OutOfScopeError(f"host not in scope: {host}")
        if not self.allow_private and self.is_private_host(host):
            raise OutOfScopeError(
                f"host resolves to a private/internal address: {host} "
                "(set allow_private=True to override)"
            )
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return Target(
            url=url,
            scheme=parts.scheme,
            host=host,
            port=port,
            path=parts.path or "/",
        )

    def filter_in_scope(self, urls: Iterable[str]) -> List[str]:
        out: List[str] = []
        for u in urls:
            try:
                self.check_url(u)
            except OutOfScopeError:
                continue
            out.append(u)
        return out

    @classmethod
    def from_target_url(cls, url: str, **kwargs) -> "Scope":
        """Convenience: build a single-host scope from a target URL."""
        host = urlsplit(url).hostname
        allow: List[str] = [host] if host else []
        scope = cls(allow=allow, **kwargs)
        return scope
