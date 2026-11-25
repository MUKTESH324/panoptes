"""Authentication rate-limit / brute-force-protection check (opt-in).

Sends a burst of failed logins to the login form and reports if none are
throttled (no 429/503, no lockout/too-many-attempts message). It uses a
**random, non-existent username** so it never locks out the real test account —
it probes IP/endpoint-level throttling, not a specific account.

This generates failed-login traffic, so it is opt-in (``--auth-ratelimit``).
"""

from __future__ import annotations

import secrets
from typing import List
from urllib.parse import urljoin

from .config import LoginConfig
from .login import parse_login_form
from .models import Confidence, Finding, Severity
from .utils.http import response_text

_BLOCK_HINTS = ("too many", "rate limit", "try again later", "temporarily locked",
                "locked out", "captcha")


async def check_auth_rate_limit(login: LoginConfig, client, attempts: int = 12) -> List[Finding]:
    if not login.url:
        return []
    try:
        page = await client.get(login.url)
    except Exception:  # noqa: BLE001
        return []
    form = parse_login_form(response_text(page), login.password_field)
    user_field = login.username_field or (form.username_field if form else "username")
    pass_field = login.password_field or (form.password_field if form else "password")
    action = urljoin(login.url, (login.action or (form.action if form else "")) or login.url)
    method = (login.method or (form.method if form else "post")).lower()

    # Random, non-existent account => we test throttling, never lock a real user.
    user = "panoptes_probe_" + secrets.token_hex(4)
    statuses: List[int] = []
    for _ in range(attempts):
        data = dict(form.hidden) if form else {}
        data[user_field] = user
        data[pass_field] = "wrong-" + secrets.token_hex(3)
        data.update(login.extra)
        try:
            if method == "get":
                resp = await client.get(action, params=data)
            else:
                resp = await client.post(action, data=data)
        except Exception:  # noqa: BLE001
            break
        statuses.append(resp.status_code)
        body = response_text(resp).lower()
        if resp.status_code in (429, 503) or any(h in body for h in _BLOCK_HINTS):
            return []  # throttling / lockout observed => protected

    if len(statuses) < attempts:
        return []
    return [
        Finding(
            plugin="auth-rate-limit",
            title="No rate limiting on authentication",
            severity=Severity.MEDIUM,
            description=(
                f"{len(statuses)} rapid failed logins were accepted with no "
                "throttling, lockout, or CAPTCHA — enabling credential brute "
                "force and password spraying."
            ),
            confidence=Confidence.TENTATIVE,
            cwe="CWE-307",
            owasp="A07:2021 Identification and Authentication Failures",
            evidence=f"{len(statuses)} attempts, status codes seen: {sorted(set(statuses))}.",
            remediation=(
                "Rate-limit failed logins per IP/account, add progressive delays "
                "or lockout, and consider CAPTCHA after repeated failures."
            ),
            url=action,
            tags=["auth", "rate-limit", "active"],
        )
    ]
