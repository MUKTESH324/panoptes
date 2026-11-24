"""Command-line interface for Argus."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .ai import available_providers
from .config import Config
from .engine import Engine
from .models import Severity
from .plugins.base import discover
from .reporting import render
from .scope import AuthorizationError, OutOfScopeError, Scope

_BANNER = r"""
    _
   / \   _ __ __ _ _   _ ___   Argus v{v}
  / _ \ | '__/ _` | | | / __|  AI-assisted web vuln scanner
 / ___ \| | | (_| | |_| \__ \  authorized testing only
/_/   \_\_|  \__, |\__,_|___/
             |___/
""".format(v=__version__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="Argus — AI-assisted web vulnerability scanner for AUTHORIZED testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # scan
    s = sub.add_parser("scan", help="scan a target")
    s.add_argument("target", nargs="?", help="target URL, e.g. https://example.com")
    s.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="affirm you have explicit written permission to test the target",
    )
    s.add_argument("--config", help="path to a YAML config file")
    s.add_argument("--scope", nargs="*", default=[], metavar="HOST",
                   help="additional in-scope hosts/wildcards (e.g. *.example.com)")
    s.add_argument("--deny", nargs="*", default=[], metavar="HOST",
                   help="hosts to always exclude")
    s.add_argument("--allow-private", action="store_true",
                   help="permit private/internal addresses (dangerous)")
    s.add_argument("--plugins", nargs="*", default=[], metavar="NAME",
                   help="only run these plugins")
    s.add_argument("--exclude", nargs="*", default=[], metavar="NAME",
                   help="skip these plugins")
    s.add_argument("--format", default="markdown",
                   choices=["json", "sarif", "markdown", "md", "html"],
                   help="report format")
    s.add_argument("--output", "-o", help="write report to file instead of stdout")
    s.add_argument("--rps", type=float, help="max requests per second")
    s.add_argument("--max-urls", type=int, help="cap on URLs to crawl")
    s.add_argument("--depth", type=int, help="max crawl depth")
    s.add_argument("--no-crawl", action="store_true", help="scan only the target URL")
    s.add_argument("--insecure", action="store_true", help="do not verify TLS certs")
    s.add_argument("--ai-provider", choices=available_providers(),
                   help="enable an AI payload provider")
    s.add_argument("--ai-model", help="model name for the AI provider")
    s.add_argument("--fail-on", choices=[str(x) for x in Severity],
                   help="exit non-zero if any finding >= this severity")
    s.add_argument("-v", "--verbose", action="store_true")

    # plugins
    sub.add_parser("plugins", help="list available check plugins")
    # providers
    sub.add_parser("providers", help="list available AI providers")
    return p


def _load_config(args: argparse.Namespace) -> Config:
    cfg = Config.load(args.config) if args.config else Config()
    if args.target:
        cfg.target = args.target
    if args.plugins:
        cfg.plugins = args.plugins
    if args.exclude:
        cfg.exclude_plugins = args.exclude
    if args.rps is not None:
        cfg.http.requests_per_second = args.rps
    if args.insecure:
        cfg.http.verify_tls = False
    if args.max_urls is not None:
        cfg.crawl.max_urls = args.max_urls
    if args.depth is not None:
        cfg.crawl.max_depth = args.depth
    if args.no_crawl:
        cfg.crawl.enabled = False
        cfg.crawl.max_depth = 0
    if args.ai_provider:
        cfg.ai.enabled = args.ai_provider != "null"
        cfg.ai.provider = args.ai_provider
    if args.ai_model:
        cfg.ai.model = args.ai_model

    # Scope: allowlist = target host + any extra --scope, minus --deny.
    extra = list(args.scope)
    cfg.scope.allow = list(dict.fromkeys(cfg.scope.allow + extra))
    cfg.scope.deny = list(dict.fromkeys(cfg.scope.deny + list(args.deny)))
    cfg.scope.allow_private = cfg.scope.allow_private or args.allow_private
    cfg.scope.authorized = cfg.scope.authorized or args.i_am_authorized
    return cfg


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.target and not args.config:
        print("error: a target URL or --config is required", file=sys.stderr)
        return 2
    cfg = _load_config(args)
    if not cfg.target:
        print("error: no target specified", file=sys.stderr)
        return 2

    scope = Scope(
        allow=cfg.scope.allow or _host_list(cfg.target),
        deny=cfg.scope.deny,
        allow_private=cfg.scope.allow_private,
        authorized=cfg.scope.authorized,
    )

    if args.verbose:
        print(_BANNER, file=sys.stderr)
        print(f"[*] target: {cfg.target}", file=sys.stderr)
        print(f"[*] scope:  allow={scope.allow} deny={scope.deny}", file=sys.stderr)

    try:
        scope.require_authorization()
    except AuthorizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    try:
        import asyncio

        result = asyncio.run(Engine(cfg, scope).run())
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:  # pragma: no cover
        print("aborted", file=sys.stderr)
        return 130

    report = render(result, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[+] wrote {args.format} report to {args.output}", file=sys.stderr)
        _print_summary(result)
    else:
        print(report)

    if args.fail_on:
        threshold = Severity.from_name(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def _cmd_plugins(_args: argparse.Namespace) -> int:
    for name, cls in sorted(discover().items()):
        kind = "passive" if getattr(cls, "passive", True) else "active "
        print(f"  [{kind}] {name:20s} {cls.description}")
    return 0


def _cmd_providers(_args: argparse.Namespace) -> int:
    for name in available_providers():
        print(f"  {name}")
    return 0


def _print_summary(result) -> None:
    c = result.counts_by_severity()
    print(
        f"[+] {len(result.findings)} findings "
        f"(critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}) across {result.urls_scanned} URLs",
        file=sys.stderr,
    )


def _host_list(target: str) -> List[str]:
    from urllib.parse import urlsplit

    host = urlsplit(target).hostname
    return [host] if host else []


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "plugins":
        return _cmd_plugins(args)
    if args.command == "providers":
        return _cmd_providers(args)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
