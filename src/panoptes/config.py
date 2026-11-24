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
class Config:
    target: str = ""
    plugins: List[str] = field(default_factory=list)  # empty == all
    exclude_plugins: List[str] = field(default_factory=list)
    http: HttpConfig = field(default_factory=HttpConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        data = dict(data or {})
        nested = {
            "http": HttpConfig,
            "crawl": CrawlConfig,
            "ai": AIConfig,
            "scope": ScopeConfig,
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
