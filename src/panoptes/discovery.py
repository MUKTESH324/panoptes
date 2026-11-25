"""Content and parameter discovery (wordlist brute-forcing).

* **Content discovery** requests a wordlist of common paths at the site root and
  reports the ones that exist. A random-path *soft-404 baseline* is taken first
  so catch-all 200 responses don't cause false positives. Discovered 200 pages
  are added to the scan surface so every check also runs on them.
* **Parameter discovery** sends candidate parameter names with a unique marker
  and reports those the app *reflects* — hidden parameters worth testing.

All requests are scope-enforced and rate-limited by the shared HTTP client.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from .models import Confidence, Finding, Severity
from .utils.http import response_text
from .utils.urls import origin

_WORDLIST = Path(__file__).parent / "data" / "wordlist.txt"
_PARAMS = Path(__file__).parent / "data" / "params.txt"


def _load_lines(path: Path, override: Optional[str] = None) -> List[str]:
    src = Path(override).expanduser() if override else path
    try:
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def load_wordlist(override: Optional[str] = None) -> List[str]:
    return _load_lines(_WORDLIST, override)


def load_params(override: Optional[str] = None) -> List[str]:
    return _load_lines(_PARAMS, override)



async def discover_content(
    target: str, client, pages: Dict[str, httpx.Response],
    wordlist: Optional[List[str]] = None, max_words: int = 400,
) -> List[Finding]:
    root = origin(target)
    words = (wordlist if wordlist is not None else load_wordlist())[:max_words]

    # Soft-404 baseline from a random path (length AND body content).
    base_status, base_len, base_body = 404, 0, ""
    try:
        base = await client.get(root + "/" + secrets.token_hex(10))
        base_body = response_text(base)
        base_status, base_len = base.status_code, len(base_body)
    except Exception:  # noqa: BLE001
        pass

    findings: List[Finding] = []
    for word in words:
        path = "/" + word.lstrip("/")
        url = root + path
        if url in pages:
            continue
        try:
            resp = await client.get(url)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code not in (200, 201, 204, 301, 302, 307, 401, 403):
            continue
        # Filter catch-all soft-404s: same status plus a near-identical length
        # OR a body that closely matches the random-path baseline (handles
        # catch-alls that echo the requested path, changing only the length).
        if resp.status_code == base_status == 200:
            body = response_text(resp)
            if abs(len(body) - base_len) < 48 or _similar(body, base_body) >= 0.95:
                continue
        sev = Severity.LOW if resp.status_code in (200, 401, 403) else Severity.INFO
        findings.append(
            Finding(
                plugin="content-discovery",
                title=f"Discovered path {path} ({resp.status_code})",
                severity=sev,
                description="A path from the discovery wordlist exists on the server.",
                confidence=Confidence.FIRM,
                cwe=None,
                evidence=f"GET {url} -> {resp.status_code}",
                remediation="Confirm the path should be exposed; remove or protect it otherwise.",
                url=url,
                tags=["discovery", "content", "active"],
            )
        )
        if resp.status_code == 200 and url not in pages:
            pages[url] = resp  # feed to the check plugins
    return findings


async def discover_params(
    target: str, client, params: Optional[List[str]] = None, max_params: int = 120,
) -> List[Finding]:
    names = (params if params is not None else load_params())[:max_params]
    marker = "pano" + secrets.token_hex(5)
    try:
        base = await client.get(target)
        base_text = response_text(base)
    except Exception:  # noqa: BLE001
        return []

    findings: List[Finding] = []
    for name in names:
        test_url = _with_param(target, name, marker)
        try:
            resp = await client.get(test_url)
        except Exception:  # noqa: BLE001
            continue
        body = response_text(resp)
        if marker in body and marker not in base_text:
            findings.append(
                Finding(
                    plugin="param-discovery",
                    title=f"Reflected hidden parameter '{name}'",
                    severity=Severity.INFO,
                    description=(
                        "The application reflects a parameter that is not linked "
                        "anywhere — a hidden input worth testing for injection."
                    ),
                    confidence=Confidence.FIRM,
                    evidence=f"{name}={marker} was reflected in the response.",
                    remediation="Review how this parameter is handled and encode its output.",
                    url=test_url,
                    tags=["discovery", "parameter", "active"],
                )
            )
    return findings


def _similar(a: str, b: str) -> float:
    a, b = a[:3000], b[:3000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    import difflib
    return difflib.SequenceMatcher(None, a, b).ratio()


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    sep = "&" if parts.query else ""
    query = parts.query + sep + urlencode({name: value})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

