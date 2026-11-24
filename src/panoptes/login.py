"""Login macro — authenticate by submitting a login form.

Given a login URL and credentials, Panoptes fetches the page, auto-detects the
form (the one containing a password field), carries over hidden fields such as
CSRF tokens, submits the credentials, and leaves the resulting session in the
HTTP client's cookie jar so the whole scan runs authenticated.

Field names are auto-detected but can be overridden. Success is verified with an
optional indicator string. Credentials are treated as secrets (never logged).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b([^>]*?)/?>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
_USERNAME_HINT = re.compile(r"user|email|login|phone|account|identifier", re.IGNORECASE)


def _attrs(tag: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag):
        out[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
    return out


@dataclass
class LoginForm:
    action: str
    method: str
    username_field: str
    password_field: str
    hidden: Dict[str, str]


def parse_login_form(html: str, password_field: str = "") -> Optional[LoginForm]:
    """Find the login form (the one with a password input) and describe it."""
    for attrs_str, inner in _FORM_RE.findall(html):
        inputs = [_attrs(t) for t in _INPUT_RE.findall(inner)]
        pw = None
        if password_field:
            pw = next((i for i in inputs if i.get("name") == password_field), None)
        if pw is None:
            pw = next((i for i in inputs if i.get("type", "").lower() == "password"), None)
        if pw is None:
            continue  # not the login form

        pw_name = pw.get("name", password_field or "password")
        # Username = explicit hint or the first text/email input before the password.
        user_name = ""
        for i in inputs:
            if i is pw:
                break
            t = i.get("type", "text").lower()
            name = i.get("name", "")
            if t in ("text", "email", "tel") or _USERNAME_HINT.search(name):
                user_name = name
                break
        if not user_name:
            user_name = "username"

        hidden = {
            i["name"]: i.get("value", "")
            for i in inputs
            if i.get("type", "").lower() == "hidden" and i.get("name")
        }
        form_attrs = _attrs("<x " + attrs_str + ">")
        return LoginForm(
            action=form_attrs.get("action", ""),
            method=(form_attrs.get("method", "post") or "post").lower(),
            username_field=user_name,
            password_field=pw_name,
            hidden=hidden,
        )
    return None


@dataclass
class LoginResult:
    ok: bool
    verified: bool
    message: str


async def perform_login(client, config: "LoginConfig") -> LoginResult:
    """Fetch the login page, submit credentials, return whether it worked.

    ``client`` must expose async ``get``/``post`` (ScopedHttpClient does). The
    session lands in the client's cookie jar as a side effect.
    """
    try:
        page = await client.get(config.url)
    except Exception as exc:  # noqa: BLE001
        return LoginResult(False, False, f"could not load login page: {exc}")

    form = parse_login_form(_text(page), config.password_field)
    user_field = config.username_field or (form.username_field if form else "username")
    pass_field = config.password_field or (form.password_field if form else "password")

    data: Dict[str, str] = {}
    if form:
        data.update(form.hidden)  # CSRF tokens etc.
    data[user_field] = config.username
    data[pass_field] = config.password
    data.update(config.extra)

    action = config.action or (form.action if form else "") or config.url
    action_url = urljoin(config.url, action)
    method = (config.method or (form.method if form else "post")).lower()

    try:
        if method == "get":
            resp = await client.get(action_url, params=data)
        else:
            resp = await client.post(action_url, data=data)
    except Exception as exc:  # noqa: BLE001
        return LoginResult(False, False, f"login request failed: {exc}")

    ok, verified = _verify(resp, config)
    return LoginResult(ok, verified, "login submitted" if ok else "login appears to have failed")


def _verify(resp, config: "LoginConfig") -> Tuple[bool, bool]:
    body = _text(resp)
    if config.success_indicator:
        return (config.success_indicator in body, True)
    if config.logged_out_indicator:
        return (config.logged_out_indicator not in body, True)
    # No indicator: best-effort — a non-error status and we got here.
    return (resp.status_code < 400, False)


def _text(resp) -> str:
    try:
        return resp.text[:500_000]
    except Exception:  # noqa: BLE001
        return ""


# Imported lazily to avoid a config<->login import cycle at module load.
from .config import LoginConfig  # noqa: E402
