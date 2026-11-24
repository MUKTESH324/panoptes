"""Core data models for Argus.

Plain dataclasses are used instead of a heavier modelling library so the package
has a small dependency surface and is trivial to serialize.
"""

from __future__ import annotations

import enum
import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Finding severity, ordered so higher value == more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {name!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


class Confidence(enum.IntEnum):
    """How sure the scanner is that a finding is a true positive."""

    TENTATIVE = 0
    FIRM = 1
    CERTAIN = 2

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


@dataclass(frozen=True)
class Target:
    """A normalized scan target."""

    url: str
    scheme: str
    host: str
    port: int
    path: str = "/"

    @property
    def origin(self) -> str:
        default = {"http": 80, "https": 443}.get(self.scheme)
        if default is None or self.port == default:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class Finding:
    """A single vulnerability finding."""

    plugin: str
    title: str
    severity: Severity
    description: str
    url: str
    confidence: Confidence = Confidence.FIRM
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    request: str = ""
    response: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for dedupe across scans.

        Deliberately excludes volatile fields (evidence, timestamps) so the same
        issue at the same location collapses to one fingerprint.
        """
        basis = "|".join(
            [
                self.plugin,
                self.title,
                _normalize_url(self.url),
                self.cwe or "",
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        data["confidence"] = str(self.confidence)
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ScanResult:
    """Aggregate result of a scan."""

    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    findings: List[Finding] = field(default_factory=list)
    urls_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.name.lower(): 0 for s in Severity}
        for f in self.findings:
            counts[str(f.severity)] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "urls_scanned": self.urls_scanned,
            "counts": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "meta": self.meta,
        }


def _normalize_url(url: str) -> str:
    """Normalize a URL for fingerprinting.

    Lowercases host, drops the fragment and trailing slash, and keeps query
    parameter *names* while discarding their *values*. Dropping values is
    important: injection probes embed a unique per-run marker in the value, so
    keeping it would make the same issue look new on every scan.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    keys = sorted((k, "") for k, _ in parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(keys)
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
