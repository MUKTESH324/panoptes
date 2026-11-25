"""Configuration loading and defaults.

Config can come from a YAML file, environment variables, or the CLI. The
resolution order is: defaults < YAML file < environment < explicit overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


@dataclass
class HttpConfig:
    timeout: float = 15.0
    max_concurrency: int = 10
    requests_per_second: float = 20.0
    user_agent: str = "Panoptes/0.1 (+authorized-security-testing)"
    verify_tls: bool = True
    follow_redirects: bool = True
    max_retries: int = 2


@dataclass
class CrawlConfig:
    enabled: bool = True
    max_depth: int = 2
    max_urls: int = 200
    same_origin_only: bool = True
    render: bool = False  # use a headless browser (Playwright) to also discover URLs


@dataclass
class AIConfig:
    provider: str = "null"  # null | openai | anthropic | ollama
    model: str = ""
    api_key_env: str = ""
    base_url: str = ""
    enabled: bool = False
    max_payloads: int = 8


@dataclass
class ScopeConfig:
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    allow_private: bool = False
    authorized: bool = False


@dataclass
class PortScanConfig:
    enabled: bool = False
    ports: List[int] = field(default_factory=list)  # empty => curated default set
    timeout: float = 1.5
    concurrency: int = 100
    use_nmap: bool = True


@dataclass
class AuthConfig:
    """Credentials for authenticated (behind-login) scanning.

    Headers and cookies are attached to every in-scope request. Cookies are
    bound to the target host so they are never sent to another domain (e.g.
    through a redirect). Values are treated as secrets: never logged or written
    into reports.
    """

    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.headers or self.cookies)


@dataclass
class LoginConfig:
    """Login macro — Panoptes submits a login form to obtain a session."""

    url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = ""   # auto-detected from the form when empty
    password_field: str = ""   # auto-detected from the form when empty
    action: str = ""           # auto-detected from the form when empty
    method: str = "post"
    extra: Dict[str, str] = field(default_factory=dict)
    success_indicator: str = ""      # text present only when logged in
    logged_out_indicator: str = ""   # text present only when logged out

    @property
    def active(self) -> bool:
        return bool(self.url and self.username and self.password)


@dataclass
class DiscoveryConfig:
    enabled: bool = False
    wordlist: str = ""       # path to a custom content wordlist (built-in if blank)
    params: str = ""         # path to a custom parameter wordlist (built-in if blank)
    max_words: int = 400
    max_params: int = 120


@dataclass
class NucleiConfig:
    enabled: bool = False
    timeout: float = 300.0
    extra_args: List[str] = field(default_factory=list)


@dataclass
class OobConfig:
    enabled: bool = False
    host: str = "127.0.0.1"   # address the target should call back to (advertised)
    port: int = 0             # 0 = pick a free port
    grace: float = 3.0        # seconds to wait for async callbacks


@dataclass
class AccessControlConfig:
    """Access-control / IDOR testing options."""

    enabled: bool = False
    # Optional second identity (user B) for IDOR comparison, as cookies/headers.
    idor_headers: Dict[str, str] = field(default_factory=dict)
    idor_cookies: Dict[str, str] = field(default_factory=dict)

    @property
    def has_second_identity(self) -> bool:
        return bool(self.idor_headers or self.idor_cookies)


@dataclass
class Config:
    target: str = ""
    plugins: List[str] = field(default_factory=list)  # empty == all
    exclude_plugins: List[str] = field(default_factory=list)
    stored_xss: bool = False  # opt-in: submits benign test data to forms
    auth_ratelimit: bool = False  # opt-in: sends failed logins to test throttling
    verify_xss: bool = False  # opt-in: browser-confirm XSS execution (needs Playwright)
    http: HttpConfig = field(default_factory=HttpConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    login: LoginConfig = field(default_factory=LoginConfig)
    portscan: PortScanConfig = field(default_factory=PortScanConfig)
    access: AccessControlConfig = field(default_factory=AccessControlConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    oob: OobConfig = field(default_factory=OobConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        data = dict(data or {})
        nested = {
            "http": HttpConfig,
            "crawl": CrawlConfig,
            "ai": AIConfig,
            "scope": ScopeConfig,
            "auth": AuthConfig,
            "login": LoginConfig,
            "portscan": PortScanConfig,
            "access": AccessControlConfig,
            "discovery": DiscoveryConfig,
            "nuclei": NucleiConfig,
            "oob": OobConfig,
        }
        kwargs: Dict[str, Any] = {}
        for f in fields(cls):
            if f.name in nested and f.name in data:
                sub = nested[f.name]
                valid = {sf.name for sf in fields(sub)}
                kwargs[f.name] = sub(**{k: v for k, v in (data[f.name] or {}).items() if k in valid})
            elif f.name in data:
                kwargs[f.name] = data[f.name]
        return cls(**kwargs)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        data: Dict[str, Any] = {}
        if path:
            import yaml  # local import so PyYAML is only needed when used

            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        cfg = cls.from_dict(data)
        cfg._apply_env()
        return cfg

    def _apply_env(self) -> None:
        if os.getenv("PANOPTES_TARGET"):
            self.target = os.environ["PANOPTES_TARGET"]
        if os.getenv("PANOPTES_AUTHORIZED", "").lower() in ("1", "true", "yes"):
            self.scope.authorized = True
        if os.getenv("PANOPTES_RPS"):
            try:
                self.http.requests_per_second = float(os.environ["PANOPTES_RPS"])
            except ValueError:
                pass
