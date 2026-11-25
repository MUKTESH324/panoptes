"""Active check: GraphQL endpoint exposure and introspection.

Probes common GraphQL endpoints (once per host) and sends a standard
introspection query. If the server returns a schema, introspection is enabled —
it hands an attacker the full API surface. It also flags a reachable GraphQL
endpoint on its own. Non-destructive: it only runs introspection and a trivial
query, never mutations.
"""

from __future__ import annotations

import json
import secrets
from typing import Set
from urllib.parse import urlsplit

from ..models import Confidence, Severity
from ..utils.http import response_text
from .base import Plugin, ScanContext, register

_PATHS = [
    "/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/graphiql", "/api/gql", "/index.php?graphql",
]
_INTROSPECTION = {
    "query": "query{__schema{queryType{name} types{name kind}}}"
}


@register
class GraphQL(Plugin):
    name = "graphql"
    description = "Detects GraphQL endpoints and enabled introspection."
    passive = False

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    async def check(self, ctx: ScanContext) -> None:
        parts = urlsplit(ctx.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._seen:
            return
        self._seen.add(origin)

        candidates = [origin + p for p in _PATHS]
        if "graphql" in ctx.url.lower() or "/gql" in ctx.url.lower():
            candidates.insert(0, ctx.url)

        for url in candidates:
            try:
                resp = await ctx.client.post(url, json=_INTROSPECTION)
            except Exception:  # noqa: BLE001
                continue
            body = response_text(resp)
            looks_graphql = (
                '"data"' in body or '"errors"' in body or "__schema" in body
            )
            if not looks_graphql:
                continue

            if "__schema" in body and '"types"' in body:
                self._report(
                    ctx,
                    title="GraphQL introspection is enabled",
                    severity=Severity.MEDIUM,
                    description=(
                        "The GraphQL endpoint answers introspection queries, "
                        "exposing the full schema (types, queries, mutations) and "
                        "greatly easing attacks against the API."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    evidence=f"Introspection query to {url} returned a schema.",
                    remediation=(
                        "Disable introspection in production, require "
                        "authentication, and add query depth/complexity limits."
                    ),
                    url=url,
                    tags=["graphql", "active"],
                )
                await self._abuse_tests(ctx, url)
                return
            # Reachable endpoint but introspection blocked — still worth noting.
            self._report(
                ctx,
                title="GraphQL endpoint exposed",
                severity=Severity.INFO,
                description="A GraphQL endpoint is reachable; review authentication and limits.",
                confidence=Confidence.FIRM,
                evidence=f"GraphQL-style response from {url}.",
                remediation="Ensure the endpoint requires auth and enforces query limits.",
                url=url,
                tags=["graphql", "active"],
            )
            await self._abuse_tests(ctx, url)
            return

    async def _abuse_tests(self, ctx: ScanContext, url: str) -> None:
        """Query-abuse checks on a confirmed GraphQL endpoint."""
        # Field-suggestion leakage: a misspelled field triggers "Did you mean".
        token = secrets.token_hex(3)
        try:
            resp = await ctx.client.post(
                url, json={"query": "query{__typename panoptes_nope_" + token + "}"})
            if "did you mean" in response_text(resp).lower():
                self._report(
                    ctx,
                    title="GraphQL field suggestions enabled (schema leakage)",
                    severity=Severity.LOW,
                    description=(
                        "Error messages suggest valid field names ('Did you "
                        "mean…'), letting an attacker reconstruct the schema even "
                        "when introspection is disabled."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-200",
                    evidence="Misspelled field returned a 'Did you mean' suggestion.",
                    remediation="Disable field suggestions in production error responses.",
                    url=url,
                    tags=["graphql", "abuse", "active"],
                )
        except Exception:  # noqa: BLE001
            pass

        # Query batching: an array of queries processed together enables
        # request amplification (e.g. brute forcing within one HTTP request).
        try:
            resp = await ctx.client.post(
                url, json=[{"query": "{__typename}"}, {"query": "{__typename}"}])
            data = json.loads(response_text(resp))
            if isinstance(data, list) and len(data) >= 2:
                self._report(
                    ctx,
                    title="GraphQL query batching enabled (amplification)",
                    severity=Severity.LOW,
                    description=(
                        "The endpoint executes batched query arrays, so one HTTP "
                        "request can run many operations — useful for brute force "
                        "and for bypassing per-request rate limits."
                    ),
                    confidence=Confidence.FIRM,
                    cwe="CWE-770",
                    evidence="A 2-query batch array returned 2 results.",
                    remediation="Disable array batching or enforce per-operation limits.",
                    url=url,
                    tags=["graphql", "abuse", "active"],
                )
        except Exception:  # noqa: BLE001
            pass

