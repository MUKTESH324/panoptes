"""Autonomous hunt orchestrator.

Combines Panoptes's scanning engine with the agentic layer into one flow:

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
from .config import AuthConfig, Config
from .crawler import Crawler
from .http_client import ScopedHttpClient
from .models import Finding, ScanResult
from .planner import Plan, Planner, recon_signals
from .plugins.base import ScanContext, select
from .portscan import PortScanner, PortScanResult
from .recommend import Recommendation, recommend
from .scope import Scope
from .utils.dedupe import dedupe_findings
from .utils.urls import hostname
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
    ports: Optional["PortScanResult"] = None
    recommendations: List["Recommendation"] = field(default_factory=list)
    ai_analysis: str = ""
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
            "ports": self.ports.to_dict() if self.ports else None,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "ai_analysis": self.ai_analysis,
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
        self._session_cookies: dict = {}

    async def run(self) -> HuntResult:
        self.scope.require_authorization()
        result = HuntResult(target=self.config.target)
        provider: AIProvider = build_provider(self.config.ai)
        result.meta["ai_provider"] = provider.name
        result.meta["authenticated"] = self.config.auth.active or self.config.login.active

        available = list(select())  # instantiated plugins; names below
        available_names = [p.name for p in available]
        planner = Planner(available=available_names)

        async with ScopedHttpClient(
            self.scope,
            self.config.http,
            auth=self.config.auth,
            cookie_domain=hostname(self.config.target),
        ) as client:
            # Login macro: authenticate before crawling so the whole scan is
            # performed as the logged-in user.
            if self.config.login.active:
                from .login import perform_login

                login_res = await perform_login(client, self.config.login)
                result.meta["login"] = login_res.ok
                if not login_res.ok:
                    result.errors.append(f"login macro: {login_res.message}")

            # Session re-auth: re-login if a page looks logged out mid-crawl.
            relogin = None
            if self.config.login.active and self.config.login.logged_out_indicator:
                async def relogin() -> None:
                    from .login import perform_login
                    await perform_login(client, self.config.login)

            crawler = Crawler(
                client, self.scope, self.config.crawl,
                relogin=relogin,
                logged_out_marker=self.config.login.logged_out_indicator,
            )
            try:
                pages = await crawler.crawl(self.config.target)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"crawl failed: {exc}")
                pages = {}
            if crawler.reauth_count:
                result.meta["reauth_count"] = crawler.reauth_count
            if self.config.target not in pages:
                try:
                    pages[self.config.target] = await client.get(self.config.target)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"could not fetch target: {exc}")

            # Optional JS-rendering discovery (headless browser) to expand surface.
            if self.config.crawl.render:
                await self._render_discover(client, pages, result)

            # Content / parameter discovery (adds discovered URLs to the surface).
            discovery_findings: List[Finding] = []
            if self.config.discovery.enabled:
                discovery_findings = await self._discovery_pass(client, pages, result)

            # Snapshot the session (e.g. a login cookie) for post-crawl passes.
            self._session_cookies = client.session_cookies()

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

            raw: List[Finding] = list(discovery_findings)
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

        # Optional port-scan recon (same authorization + scope rules).
        if self.config.portscan.enabled:
            scanner = PortScanner(
                self.scope,
                timeout=self.config.portscan.timeout,
                concurrency=self.config.portscan.concurrency,
                use_nmap=self.config.portscan.use_nmap,
            )
            host = hostname(self.config.target)
            try:
                port_result = await scanner.scan(host, self.config.portscan.ports or None)
                result.ports = port_result
                result.meta["portscan_method"] = port_result.method
                raw.extend(port_result.to_findings())
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"port scan failed: {exc}")

        # Access-control / IDOR pass (needs a session to be meaningful).
        if self.config.access.enabled:
            await self._access_pass(pages, raw, result)

        # Stored-XSS pass (opt-in: submits benign test data to forms).
        if self.config.stored_xss:
            await self._stored_xss_pass(pages, raw, result)

        # Browser-driven XSS confirmation (opt-in; needs Playwright).
        if self.config.verify_xss:
            await self._verify_xss_pass(pages, raw, result)

        # Out-of-band SSRF confirmation with the bundled listener (opt-in).
        if self.config.oob.enabled:
            await self._ssrf_oob_pass(pages, raw, result)

        # Auth rate-limit pass (opt-in: sends failed logins for a random user).
        if self.config.auth_ratelimit and self.config.login.url:
            from .authratelimit import check_auth_rate_limit
            try:
                async with ScopedHttpClient(
                    self.scope, self.config.http,
                    cookie_domain=hostname(self.config.target),
                ) as arl_client:
                    raw.extend(await check_auth_rate_limit(self.config.login, arl_client))
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"auth rate-limit check failed: {exc}")

        # Optional nuclei pass (known-CVE / templated coverage).
        if self.config.nuclei.enabled:
            from .nuclei import run_nuclei
            nf, nerr = await run_nuclei(
                self.config.target, self.config.nuclei.timeout,
                self.config.nuclei.extra_args or None,
            )
            raw.extend(nf)
            result.errors.extend(nerr)
            result.errors.append(
                "note: nuclei runs against the target directly and is not bound "
                "by Panoptes' per-request scope/allowlist enforcement"
            )
            result.meta["nuclei"] = len(nf)

        findings = dedupe_findings(raw)

        # Validation gate.
        gate = ValidationGate(strict=self.strict)
        validation = gate.evaluate(findings)
        result.validation = validation
        result.verdicts = validation.verdicts

        kept = validation.kept
        # Exploit chains built from kept findings.
        result.chains = ChainBuilder().build(kept)

        # Recommended next steps from findings + open ports.
        result.recommendations = recommend(kept, result.ports)

        # Optional AI analyst executive summary (opt-in; needs an AI provider).
        if self.config.ai_report and self.config.ai.enabled:
            from .analyst import analyze_hunt
            try:
                result.ai_analysis = await analyze_hunt(result, provider)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"ai report failed: {exc}")

        # Persist + diff.
        if self.brain is not None:
            run_id = self.brain.start_run(self.config.target)
            result.diff = self.brain.record(self.config.target, kept, run_id)
            self.brain.finish_run(run_id, len(kept))

        result.finished_at = time.time()
        return result

    async def _verify_xss_pass(self, pages, raw, result) -> None:
        from .xss_verify import XssVerifier, verify_reflected, verify_stored
        if not XssVerifier.available():
            result.meta["xss_verify"] = False
            result.errors.append(
                "verify-xss requested but Playwright is not installed "
                "(pip install 'panoptes-scanner[browser]' && playwright install chromium)"
            )
            return
        verifier = XssVerifier(
            self.scope, timeout=self.config.http.timeout,
            cookies={**self.config.auth.cookies, **self._session_cookies},
        )
        try:
            raw.extend(await verify_reflected(list(pages), verifier))
            if self.config.stored_xss:
                auth = AuthConfig(
                    headers=dict(self.config.auth.headers),
                    cookies={**self.config.auth.cookies, **self._session_cookies},
                )
                async with ScopedHttpClient(
                    self.scope, self.config.http, auth=auth,
                    cookie_domain=hostname(self.config.target),
                ) as client:
                    raw.extend(await verify_stored(pages, verifier, client))
            result.meta["xss_verify"] = True
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"xss verification failed: {exc}")

    async def _ssrf_oob_pass(self, pages, raw, result) -> None:
        from .oob import OobListener
        from .ssrf_oob import run_ssrf_oob
        listener = OobListener(advertise_host=self.config.oob.host,
                               port=self.config.oob.port)
        try:
            listener.start()
            auth = AuthConfig(
                headers=dict(self.config.auth.headers),
                cookies={**self.config.auth.cookies, **self._session_cookies},
            )
            async with ScopedHttpClient(
                self.scope, self.config.http, auth=auth,
                cookie_domain=hostname(self.config.target),
            ) as client:
                raw.extend(await run_ssrf_oob(pages, client, listener, self.config.oob.grace))
            result.meta["oob_interactions"] = len(listener.interactions())
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"ssrf-oob pass failed: {exc}")
        finally:
            listener.stop()

    async def _discovery_pass(self, client, pages, result) -> List[Finding]:
        from .discovery import (
            discover_content,
            discover_params,
            load_params,
            load_wordlist,
        )

        findings: List[Finding] = []
        cfg = self.config.discovery
        try:
            findings += await discover_content(
                self.config.target, client, pages,
                load_wordlist(cfg.wordlist or None), cfg.max_words,
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"content discovery failed: {exc}")
        try:
            findings += await discover_params(
                self.config.target, client,
                load_params(cfg.params or None), cfg.max_params,
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"parameter discovery failed: {exc}")
        return findings

    async def _render_discover(self, client, pages, result) -> None:
        """Use a headless browser to discover more in-scope URLs, then fetch them."""
        from .browser_crawler import BrowserCrawler

        bc = BrowserCrawler(self.scope, max_pages=self.config.crawl.max_urls)
        if not bc.available():
            result.meta["rendered"] = False
            result.errors.append(
                "render requested but Playwright is not installed "
                "(pip install 'panoptes-scanner[browser]' && playwright install chromium)"
            )
            return
        session = {**self.config.auth.cookies, **client.session_cookies()}
        found, errs = await bc.discover(self.config.target, cookies=session or None)
        result.errors.extend(errs)
        added = 0
        for url in found:
            if url in pages or len(pages) >= self.config.crawl.max_urls:
                continue
            try:
                pages[url] = await client.get(url)
                added += 1
            except Exception:  # noqa: BLE001
                continue
        result.meta["rendered"] = True
        result.meta["rendered_urls_added"] = added

    async def _stored_xss_pass(self, pages, raw, result) -> None:
        from .stored_xss import find_stored_xss

        auth = AuthConfig(
            headers=dict(self.config.auth.headers),
            cookies={**self.config.auth.cookies, **self._session_cookies},
        )
        try:
            async with ScopedHttpClient(
                self.scope, self.config.http, auth=auth,
                cookie_domain=hostname(self.config.target),
            ) as client:
                raw.extend(await find_stored_xss(pages, client))
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"stored-xss pass failed: {exc}")

    async def _access_pass(self, pages, raw, result) -> None:
        """Access-control / IDOR checks using fresh anonymous / user-B clients."""
        authenticated = self.config.login.active or self.config.auth.active
        if authenticated:
            from .access import find_missing_auth
            try:
                async with ScopedHttpClient(self.scope, self.config.http) as anon:
                    raw.extend(await find_missing_auth(pages, anon))
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"access-control (missing-auth) failed: {exc}")

        if self.config.access.has_second_identity:
            from .access import (
                find_idor,
                find_privilege_escalation,
                find_tenant_isolation,
            )
            auth_b = AuthConfig(
                headers=self.config.access.idor_headers,
                cookies=self.config.access.idor_cookies,
            )
            try:
                async with ScopedHttpClient(
                    self.scope, self.config.http, auth=auth_b,
                    cookie_domain=hostname(self.config.target),
                ) as client_b:
                    # The second identity exercises object-level (IDOR),
                    # function-level (privilege escalation) and tenant-level
                    # (multi-tenant) authorization in one pass.
                    raw.extend(await find_idor(pages, client_b))
                    raw.extend(await find_privilege_escalation(pages, client_b))
                    raw.extend(await find_tenant_isolation(pages, client_b))
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"access-control (authz) failed: {exc}")

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
