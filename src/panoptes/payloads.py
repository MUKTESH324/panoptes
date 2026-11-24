"""Structured payload library.

Loads the bundled YAML payload set and merges in AI-generated payloads when a
provider is configured. Every payload supports a ``{marker}`` placeholder that
is filled with a unique token per probe so reflections are attributable.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULTS: Dict[str, List[str]] = {
    "xss": ["<panoptes{marker}>", "\"'><panoptes{marker}>"],
    "sqli": ["'", "\" OR '1'='1' -- {marker}"],
    "open_redirect": ["https://panoptes-redirect-probe.example/{marker}"],
    "ssti": ["panoptes{{7*7}}{marker}"],
    "lfi": ["../../../../etc/hostname"],
    "ssrf": ["http://panoptes-ssrf-probe.example/{marker}"],
}

_DATA_FILE = Path(__file__).parent / "data" / "payloads.yaml"


@lru_cache(maxsize=1)
def _load_library() -> Dict[str, List[str]]:
    try:
        import yaml

        with open(_DATA_FILE, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        library = {str(k): [str(p) for p in v] for k, v in data.items() if v}
        # Backfill any class missing from the file.
        for k, v in _DEFAULTS.items():
            library.setdefault(k, v)
        return library
    except Exception:  # noqa: BLE001 - fall back to built-ins
        return dict(_DEFAULTS)


def new_marker() -> str:
    return "p" + secrets.token_hex(5)


def get_payloads(vuln_type: str, marker: Optional[str] = None) -> List[str]:
    """Return payloads for a vuln class, with {marker} substituted."""
    marker = marker or new_marker()
    templates = _load_library().get(vuln_type.lower(), [])
    return [t.replace("{marker}", marker) for t in templates]


def vuln_types() -> List[str]:
    return sorted(_load_library())
