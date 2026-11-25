"""Access-control / authorization testing.

Two automated checks that compare how the *same* URL answers different
identities — the class of bug (broken access control / IDOR, OWASP A01) that
dominates real-world findings and that a single-session scan can never see:

  * **missing authentication** — pages reachable with an authenticated session
    are re-requested *anonymously*; if the anonymous user gets the same page,
    access control is missing.
  * **IDOR** (optional, needs a second identity) — object-specific URLs found as
    user A are re-requested as user B; if B gets A's object, that's an insecure
    direct object reference.

Both are reported at tentative confidence (→ "needs review"), because deciding
whether a page is *meant* to be public is ultimately a human call. The checks
are deliberately conservative to keep false positives down.
"""

from __future__ import annotations

import difflib
import re
from typing import Dict, List
from urllib.parse import parse_qsl, urlsplit

import httpx

from .models import Confidence, Finding, Severity
from .utils.http import response_text

_SENSITIVE_PATH = re.compile(
    r"account|admin|dashboard|settings|profile|user|order|invoice|api|private|"
    r"manage|billing|member|portal|wallet|payment|checkout|report|secret|token",
    re.IGNORECASE,
)
_ID_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id", "order",
    "order_id", "invoice", "invoice_id", "doc", "document", "file", "num",
    "number", "pid", "oid", "key", "record", "ref", "customer", "profile",
}
_UUID_OR_NUM = re.compile(r"^[0-9]+$|^[0-9a-f]{8}-[0-9a-f]{4}-", re.IGNORECASE)
_SIM_THRESHOLD = 0.9
_MIN_BODY = 64  # don't judge access control on near-empty responses


def _similar(a: str, b: str) -> float:
    a, b = a[:4000], b[:4000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


async def find_missing_auth(authed_pages: Dict[str, httpx.Response], anon_client) -> List[Finding]:
    """Flag sensitive pages that an anonymous user can also reach."""
    findings: List[Finding] = []
    for url, authed in authed_pages.items():
        if authed.status_code != 200 or not _SENSITIVE_PATH.search(url):
            continue
        try:
            anon = await anon_client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if anon.status_code != 200:
            continue  # anonymous request was blocked/redirected — auth enforced
        a_text, b_text = response_text(authed), response_text(anon)
        if len(a_text.strip()) < _MIN_BODY:
            continue  # too little content to judge meaningfully
        if _similar(a_text, b_text) < _SIM_THRESHOLD:
            continue  # anon got something different (e.g. a login page)
        findings.append(
            Finding(
                plugin="access-control",
                title="Sensitive page reachable without authentication",
                severity=Severity.HIGH,
                description=(
                    "A page served to the authenticated session returns "
                    "effectively the same content to an anonymous user, "
                    "indicating missing authentication / access control."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-306",
                owasp="A01:2021 Broken Access Control",
                evidence=f"Anonymous GET {url} returned 200 with content matching the authenticated view.",
                remediation="Enforce authentication/authorization server-side on this endpoint.",
                url=url,
                tags=["access-control", "authz"],
            )
        )
    return findings


async def find_idor(authed_pages: Dict[str, httpx.Response], other_client) -> List[Finding]:
    """Flag object-specific URLs that a second identity can also read."""
    findings: List[Finding] = []
    for url, authed in authed_pages.items():
        if authed.status_code != 200 or not _has_object_ref(url):
            continue
        try:
            other = await other_client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if other.status_code != 200:
            continue
        a_text, b_text = response_text(authed), response_text(other)
        if len(a_text.strip()) < _MIN_BODY:
            continue  # too little content to judge meaningfully
        if _similar(a_text, b_text) < _SIM_THRESHOLD:
            continue
        findings.append(
            Finding(
                plugin="access-control",
                title="Possible IDOR — object readable by a different user",
                severity=Severity.HIGH,
                description=(
                    "An object-specific URL returns the same content to a second "
                    "user's session, suggesting an insecure direct object "
                    "reference (missing object-level authorization)."
                ),
                confidence=Confidence.TENTATIVE,
                cwe="CWE-639",
                owasp="A01:2021 Broken Access Control",
                evidence=f"User B GET {url} returned 200 matching user A's response.",
                remediation=(
                    "Enforce per-object ownership checks server-side; never trust "
                    "a client-supplied identifier without an authorization check."
                ),
                url=url,
                tags=["access-control", "idor", "authz"],
            )
        )
    return findings


def _has_object_ref(url: str) -> bool:
    parts = urlsplit(url)
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in _ID_PARAMS and value:
            return True
    return any(_UUID_OR_NUM.match(seg) for seg in parts.path.split("/") if seg)
