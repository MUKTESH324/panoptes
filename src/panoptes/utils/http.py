"""Small HTTP response helpers shared across plugins and passes."""

from __future__ import annotations


def response_text(response, limit: int = 500_000) -> str:
    """Return a response body as text, capped and never raising.

    Decoding can fail (bad encoding, binary body) or a body may be huge; this
    returns at most ``limit`` characters and an empty string on any error.
    """
    try:
        return response.text[:limit]
    except Exception:  # noqa: BLE001 - decoding/stream errors are non-fatal
        return ""
