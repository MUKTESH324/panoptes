"""URL helpers shared across the crawler, engine and analysis passes."""

from __future__ import annotations

from urllib.parse import urlsplit


def origin(url: str) -> str:
    """Return ``scheme://host[:port]`` lowercased (for same-origin comparisons)."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()


def hostname(url: str) -> str:
    """Return the host of a URL (lowercased by urllib), or '' on error."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""
