"""Lightweight HTML form parser (regex-based, no BeautifulSoup)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FIELD_RE = re.compile(r"<(input|textarea|select)\b([^>]*?)/?>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")

_TEXTY = {"text", "search", "url", "email", "tel", "", "password", "textarea"}


def _attrs(s: str) -> Dict[str, str]:
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
            for m in _ATTR_RE.finditer(s)}


@dataclass
class Form:
    action: str
    method: str
    hidden: Dict[str, str] = field(default_factory=dict)
    text_fields: List[str] = field(default_factory=list)
    all_fields: Dict[str, str] = field(default_factory=dict)


def parse_forms(html: str) -> List[Form]:
    forms: List[Form] = []
    for attrs_str, inner in _FORM_RE.findall(html):
        fa = _attrs(attrs_str)
        form = Form(action=fa.get("action", ""),
                    method=(fa.get("method", "get") or "get").lower())
        for tag, field_attrs in _FIELD_RE.findall(inner):
            ia = _attrs(field_attrs)
            name = ia.get("name")
            if not name:
                continue
            value = ia.get("value", "")
            form.all_fields[name] = value
            typ = tag.lower() if tag.lower() != "input" else ia.get("type", "text").lower()
            if typ == "hidden":
                form.hidden[name] = value
            elif typ in _TEXTY:
                form.text_fields.append(name)
        forms.append(form)
    return forms
