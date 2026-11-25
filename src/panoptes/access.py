"""Access-control / authorization testing.

Checks that compare how the *same* URL answers different identities — the class
of bug (broken access control, OWASP A01) that dominates real-world findings and
that a single-session scan can never see:

  * **missing authentication** — pages reachable with an authenticated session
    are re-requested *anonymously*; if the anonymous user gets the same page,
    access control is missing.
  * **IDOR** — object-specific URLs found as user A are re-requested as user B;
    if B gets A's object, that's an insecure direct object reference.
  * **vertical privilege escalation** — privileged/admin pages are re-requested
    as a lower-privileged identity; if it gets the privileged content, function-
    level authorization is missing.
  * **multi-tenant isolation** — tenant-scoped resources are re-requested as an
    identity from a different tenant; if it gets tenant A's data, isolation is
    broken.

The last three need a configured second identity (``access.idor_*``). All are
reported at tentative confidence (→ "needs review") and kept conservative
(status 200, non-empty, near-identical content) to limit false positives.
"""

from __future__ import annotations

import difflib
import re
from typing import Callable, Dict, List
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

# Privileged/admin functionality (for vertical privilege-escalation testing).
_PRIVILEGED_PATH = re.compile(
    r"/admin|administrator|/manage|管理|moderat|/console|/internal|backoffice|"
    r"/staff|superuser|/roles?|permission|/users\b|/audit|approve|/system|"
    r"/config(uration)?\b|/api/admin|sudo|/root\b",
    re.IGNORECASE,
)
# Tenant-scoping identifiers (for multi-tenant isolation testing).
_TENANT_PARAMS = {
    "tenant", "tenant_id", "tenantid", "org", "org_id", "orgid", "organization",
    "organization_id", "company", "company_id", "account_id", "workspace",
    "workspace_id", "team", "team_id", "project_id", "customer_id", "realm", "site_id",
}
_TENANT_PATH = re.compile(
    r"/(?:tenants?|orgs?|organizations?|workspaces?|teams?|companies|accounts?)/[^/]+",
    re.IGNORECASE,
)


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


async def _two_identity_pass(
    authed_pages: Dict[str, httpx.Response], other_client,
    predicate: Callable[[str], bool], make: Callable[[str], Finding],
) -> List[Finding]:
    """Shared engine: re-request URLs matching ``predicate`` as a second identity
    and emit ``make(url)`` when the second identity gets equivalent content."""
    findings: List[Finding] = []
    for url, authed in authed_pages.items():
        if authed.status_code != 200 or not predicate(url):
            continue
        try:
            other = await other_client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if other.status_code != 200:
            continue  # second identity was denied -> authorization enforced
        a_text, b_text = response_text(authed), response_text(other)
        if len(a_text.strip()) < _MIN_BODY or _similar(a_text, b_text) < _SIM_THRESHOLD:
            continue
        findings.append(make(url))
    return findings


async def find_privilege_escalation(authed_pages, other_client) -> List[Finding]:
    """Vertical priv-esc: a lower-privileged identity reaches admin/privileged pages."""
    def make(url: str) -> Finding:
        return Finding(
            plugin="access-control",
            title="Possible vertical privilege escalation",
            severity=Severity.HIGH,
            description=(
                "A privileged/administrative page returns the same content to a "
                "second, lower-privileged identity, indicating missing "
                "function-level authorization (vertical privilege escalation)."
            ),
            confidence=Confidence.TENTATIVE,
            cwe="CWE-269",
            owasp="A01:2021 Broken Access Control",
            evidence=f"Lower-privileged identity GET {url} returned 200 matching the privileged view.",
            remediation=(
                "Enforce role/function-level authorization server-side on every "
                "privileged action, not just by hiding UI links."
            ),
            url=url,
            tags=["access-control", "privilege-escalation", "authz"],
        )

    return await _two_identity_pass(authed_pages, other_client, _is_privileged, make)


async def find_tenant_isolation(authed_pages, other_client) -> List[Finding]:
    """Multi-tenant: a different-tenant identity reaches tenant-scoped resources."""
    def make(url: str) -> Finding:
        return Finding(
            plugin="access-control",
            title="Possible cross-tenant data access (broken tenant isolation)",
            severity=Severity.HIGH,
            description=(
                "A tenant-scoped resource returns the same content to an identity "
                "from a different tenant, suggesting broken multi-tenant isolation."
            ),
            confidence=Confidence.TENTATIVE,
            cwe="CWE-639",
            owasp="A01:2021 Broken Access Control",
            evidence=f"Other-tenant identity GET {url} returned 200 matching tenant A's data.",
            remediation=(
                "Scope every query by the authenticated tenant server-side; never "
                "trust a client-supplied tenant/org identifier."
            ),
            url=url,
            tags=["access-control", "multi-tenant", "authz"],
        )

    return await _two_identity_pass(authed_pages, other_client, _is_tenant_scoped, make)


def _is_privileged(url: str) -> bool:
    return bool(_PRIVILEGED_PATH.search(url))


def _is_tenant_scoped(url: str) -> bool:
    parts = urlsplit(url)
    if _TENANT_PATH.search(parts.path):
        return True
    return any(name.lower() in _TENANT_PARAMS and value
               for name, value in parse_qsl(parts.query, keep_blank_values=True))
