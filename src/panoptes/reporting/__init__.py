"""Report renderers."""

from __future__ import annotations

from typing import Callable, Dict

from ..models import ScanResult
from .html import render_html
from .json_report import render_json
from .markdown import render_markdown
from .sarif import render_sarif

RENDERERS: Dict[str, Callable[[ScanResult], str]] = {
    "json": render_json,
    "sarif": render_sarif,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
}


def render(result: ScanResult, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt not in RENDERERS:
        raise ValueError(f"unknown report format: {fmt} (have {list(RENDERERS)})")
    return RENDERERS[fmt](result)


__all__ = ["render", "RENDERERS", "render_html", "render_markdown", "render_sarif", "render_json"]
