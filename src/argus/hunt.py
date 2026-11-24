"""Autonomous hunt orchestrator.

Combines Argus's scanning engine with the agentic layer into one flow:

    recon (crawl + passive)  ->  plan  ->  phased checks  ->  validate
        ->  record in brain (diff vs. last run)  ->  build exploit chains

The result is a single :class:`HuntResult` that a human (or another agent) can
act on: validated findings, dropped likely-false-positives, inferred chains,
and what changed since the previous run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from .ai import AIProvider, build_provider
from .brain import Brain, RunDiff
from .chains import Chain, ChainBuilder
from .config import Config
from .crawler import Crawler
from .http_client import ScopedHttpClient
from .models import Finding, ScanResult
from .planner import Plan, Planner, recon_signals
from .plugins.base import ScanContext, select
from .scope import Scope
from .utils.dedupe import dedupe_findings
from .validation import ValidationGate, ValidationResult, Verdict


@dataclass
class HuntResult:
    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    urls_scanned: int = 0
    plan: Optional[Plan] = None
    signals: Optional[dict] = None
    validation: Optional[ValidationResult] = None
    verdicts: List[Verdict] = field(default_factory=list)
    chains: List[Chain] = field(default_factory=list)
    diff: Optional[RunDiff] = None
    errors: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    @property
    def findings(self) -> List[Finding]:
        return self.validation.kept if self.validation else []

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "duration": self.duration,
            "urls_scanned": self.urls_scanned,
            "plan": self.plan.to_dict() if self.plan else None,
            "signals": self.signals,
            "validation": {
                **(self.validation.summary() if self.validation else {}),
                "verdicts": [v.to_dict() for v in self.verdicts],
            },
            "findings": [f.to_dict() for f in self.findings],
            "likely_false_positives": [
                f.to_dict() for f in (self.validation.likely_fp if self.validation else [])
            ],
            "chains": [c.to_dict() for c in self.chains],
            "diff": self.diff.to_dict() if self.diff else None,
            "errors": self.errors,
            "meta": self.meta,
        }


class Hunt:
    def __init__(
        self,
        config: Config,
        scope: Scope,
        brain: Optional[Brain] = None,
        strict: bool = False,
    ) -> None:
        self.config = config
        self.scope = scope
        self.brain = brain
        self.strict = strict

    async def run(self) -> HuntResult:
        self.scope.require_authorization()
        result = HuntResult(target=self.config.target)
        provider: AIProvider = build_provider(self.config.ai)
        result.meta["ai_provider"] = provider.name

        available = list(select())  # instantiated plugins; names below
        available_names = [p.name for p in available]
        planner = Planner(available=available_names)

        async with ScopedHttpClient(self.scope, self.config.http) as client:
            crawler = Crawler(client, self.scope, self.config.crawl)
            try:
                pages = await crawler.crawl(self.config.target)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"crawl failed: {exc}")
                pages = {}
            if self.config.target not in pages:
                try:
                    pages[self.config.target] = await client.get(self.config.target)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"could not fetch target: {exc}")

            result.urls_scanned = len(pages)

            signals = recon_signals(pages)
            result.signals = {
                "tech": signals.tech,
                "waf": signals.waf,
                "has_params": signals.has_params,
                "url_count": signals.url_count,
            }
            plan = planner.plan(signals)
            # Respect an explicit plugin allow/deny from config.
            if self.config.plugins:
                for ph in plan.phases:
                    ph.plugins = [p for p in ph.plugins if p in set(self.config.plugins)]
            result.plan = plan

            raw: List[Finding] = []
            for phase in plan.phases:
                plugins = select(include=phase.plugins, exclude=self.config.exclude_plugins or None)
                for url, response in pages.items():
                    ctx = ScanContext(url=url, client=client, response=response, ai=provider)
                    for plugin in plugins:
                        try:
                            await plugin.check(ctx)
                        except Exception as exc:  # noqa: BLE001
                            result.errors.append(f"{plugin.name} failed on {url}: {exc}")
                    raw.extend(ctx.findings)

        await provider.aclose()

        findings = dedupe_findings(raw)

        # Validation gate.
        gate = ValidationGate(strict=self.strict)
        validation = gate.evaluate(findings)
        result.validation = validation
        result.verdicts = validation.verdicts

        kept = validation.kept
        # Exploit chains built from kept findings.
        result.chains = ChainBuilder().build(kept)

        # Persist + diff.
        if self.brain is not None:
            run_id = self.brain.start_run(self.config.target)
            result.diff = self.brain.record(self.config.target, kept, run_id)
            self.brain.finish_run(run_id, len(kept))

        result.finished_at = time.time()
        return result

    def as_scan_result(self, hunt: HuntResult) -> ScanResult:
        """Adapt a HuntResult to a ScanResult for the standard renderers."""
        sr = ScanResult(target=hunt.target)
        sr.started_at = hunt.started_at
        sr.finished_at = hunt.finished_at
        sr.urls_scanned = hunt.urls_scanned
        sr.findings = hunt.findings
        sr.errors = hunt.errors
        sr.meta = {
            "mode": "hunt",
            "chains": [c.to_dict() for c in hunt.chains],
            "diff": hunt.diff.to_dict() if hunt.diff else None,
        }
        return sr
