"""Helpers for injecting payloads into URL query parameters."""

from __future__ import annotations

from typing import Iterator, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def iter_param_injections(url: str, payload: str) -> Iterator[Tuple[str, str]]:
    """Yield (param_name, mutated_url) for each query param replaced by payload.

    The original value is replaced (not appended) so reflection is unambiguous.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for i, (name, _value) in enumerate(pairs):
        mutated = list(pairs)
        mutated[i] = (name, payload)
        new_query = urlencode(mutated, doseq=True)
        yield name, urlunsplit(
            (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
        )


def has_query_params(url: str) -> bool:
    return bool(parse_qsl(urlsplit(url).query, keep_blank_values=True))
