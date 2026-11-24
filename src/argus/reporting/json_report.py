"""JSON report."""

from __future__ import annotations

import json

from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False)
