"""Optional nuclei integration (known-CVE / templated coverage).

If the ``nuclei`` binary is installed, Panoptes runs it against the target and
folds its JSONL results into the findings. nuclei is a reconnaissance/known-issue
scanner maintained by ProjectDiscovery; Panoptes shells out to it for the target
URL only (single host) and parses its structured output.

nuclei is an **optional external tool** — if it is not installed, this returns no
findings and a note. Parsing is pure and unit-tested; no binary needed in CI.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import List, Optional, Tuple

from .models import Confidence, Finding, Severity

_SEV = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def parse_nuclei_jsonl(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        severity = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        refs = info.get("reference", []) or []
        if isinstance(refs, str):
            refs = [refs]
        cwe = None
        classification = info.get("classification") or {}
        cwe_ids = classification.get("cwe-id")
        if isinstance(cwe_ids, list) and cwe_ids:
            cwe = str(cwe_ids[0]).upper()
        elif isinstance(cwe_ids, str):
            cwe = cwe_ids.upper()

        findings.append(
            Finding(
                plugin="nuclei",
                title=info.get("name") or obj.get("template-id") or "nuclei finding",
                severity=severity,
                description=info.get("description") or "",
                confidence=Confidence.FIRM,
                cwe=cwe,
                evidence=f"template {obj.get('template-id', '?')} matched at "
                         f"{obj.get('matched-at') or obj.get('host', '')}",
                remediation=info.get("remediation") or "",
                url=obj.get("matched-at") or obj.get("host") or obj.get("url") or "",
                references=[str(r) for r in refs],
                tags=["nuclei"] + [str(t) for t in tags],
            )
        )
    return findings


async def run_nuclei(
    target: str, timeout: float = 300.0, extra_args: Optional[List[str]] = None,
) -> Tuple[List[Finding], List[str]]:
    """Run nuclei against a single target URL. Returns (findings, errors)."""
    if not nuclei_available():
        return [], ["nuclei is not installed (https://github.com/projectdiscovery/nuclei)"]
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-duc", "-nc"]
    if extra_args:
        cmd.extend(extra_args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except Exception as exc:  # noqa: BLE001
        return [], [f"could not launch nuclei: {exc}"]
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        return [], [f"nuclei timed out after {timeout:.0f}s"]
    findings = parse_nuclei_jsonl(stdout.decode(errors="replace"))
    errors = []
    if proc.returncode not in (0, None) and not findings:
        errors.append((stderr or b"").decode(errors="replace")[:200])
    return findings, errors
