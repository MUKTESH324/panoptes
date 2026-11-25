"""Command-line interface for Panoptes."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .ai import available_providers
from .brain import Brain
from .config import Config
from .engine import Engine
from .hunt import Hunt
from .models import Severity
from .payloads import vuln_types
from .plugins.base import discover
from .portscan import PortScanner, parse_ports
from .reporting import render
from .reporting.hunt import render_hunt
from .scope import AuthorizationError, OutOfScopeError, Scope

_BANNER = r"""
  ___                     _            Panoptes v{v}
 | _ \__ _ _ _  ___ _ __ | |_ ___ ___  the all-seeing eye
 |  _/ _` | ' \/ _ \ '_ \|  _/ -_|_-<  AI-assisted web vuln scanner
 |_| \__,_|_||_\___/ .__/ \__\___/__/  + agentic hunt mode
                    |_|                authorized testing only
""".format(v=__version__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="panoptes",
        description="Panoptes — AI-assisted web vulnerability scanner for AUTHORIZED testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"panoptes {__version__}")
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
    s.add_argument("--header", "-H", action="append", default=[], metavar="'Name: Value'",
                   help="extra header sent on every request (repeatable), e.g. -H 'Authorization: Bearer ...'")
    s.add_argument("--cookie", "-b", action="append", default=[], metavar="'name=value'",
                   help="session cookie for authenticated scans (repeatable; 'a=1; b=2' also accepted)")
    s.add_argument("--ai-provider", choices=available_providers(),
                   help="enable an AI payload provider")
    s.add_argument("--ai-model", help="model name for the AI provider")
    s.add_argument("--fail-on", choices=[str(x) for x in Severity],
                   help="exit non-zero if any finding >= this severity")
    s.add_argument("-v", "--verbose", action="store_true")

    # hunt (agentic: plan -> scan -> validate -> chain -> remember)
    h = sub.add_parser("hunt", help="autonomous hunt: plan, scan, validate, chain, remember")
    h.add_argument("target", nargs="?", help="target URL, e.g. https://example.com")
    h.add_argument("--i-am-authorized", action="store_true",
                   help="affirm you have explicit written permission to test the target")
    h.add_argument("--config", help="path to a YAML config file")
    h.add_argument("--scope", nargs="*", default=[], metavar="HOST",
                   help="additional in-scope hosts/wildcards")
    h.add_argument("--deny", nargs="*", default=[], metavar="HOST", help="hosts to exclude")
    h.add_argument("--allow-private", action="store_true",
                   help="permit private/internal addresses (dangerous)")
    h.add_argument("--plugins", nargs="*", default=[], metavar="NAME",
                   help="restrict the plan to these plugins")
    h.add_argument("--exclude", nargs="*", default=[], metavar="NAME", help="skip these plugins")
    h.add_argument("--strict", action="store_true",
                   help="drop likely-false-positive findings from the kept set")
    h.add_argument("--brain", default=".panoptes/brain.db",
                   help="path to the persistent brain database")
    h.add_argument("--no-brain", action="store_true", help="do not persist/diff this run")
    h.add_argument("--format", default="markdown", choices=["json", "markdown", "md", "html"],
                   help="hunt report format")
    h.add_argument("--output", "-o", help="write report to file instead of stdout")
    h.add_argument("--rps", type=float, help="max requests per second")
    h.add_argument("--max-urls", type=int, help="cap on URLs to crawl")
    h.add_argument("--depth", type=int, help="max crawl depth")
    h.add_argument("--no-crawl", action="store_true", help="scan only the target URL")
    h.add_argument("--render", action="store_true",
                   help="also discover URLs with a headless browser (needs Playwright)")
    h.add_argument("--stored-xss", action="store_true",
                   help="test for stored XSS by submitting benign markers to forms (writes test data)")
    h.add_argument("--auth-ratelimit", action="store_true",
                   help="test login throttling with failed logins for a random user (needs --login-url)")
    h.add_argument("--verify-xss", action="store_true",
                   help="browser-confirm XSS execution with a headless browser (needs Playwright)")
    h.add_argument("--ai-report", action="store_true",
                   help="add an LLM executive summary of the findings (needs --ai-provider)")
    h.add_argument("--ssrf-oob", action="store_true",
                   help="confirm blind SSRF with a bundled out-of-band listener")
    h.add_argument("--oob-host", metavar="ADDR",
                   help="address the target should call back to for OOB (default 127.0.0.1)")
    h.add_argument("--oob-port", type=int, help="port for the OOB listener (default: free port)")
    h.add_argument("--insecure", action="store_true", help="do not verify TLS certs")
    h.add_argument("--header", "-H", action="append", default=[], metavar="'Name: Value'",
                   help="extra header sent on every request (repeatable)")
    h.add_argument("--cookie", "-b", action="append", default=[], metavar="'name=value'",
                   help="session cookie for authenticated scans (repeatable; 'a=1; b=2' also accepted)")
    h.add_argument("--login-url", metavar="URL", help="login page URL for the login macro")
    h.add_argument("--login-user", metavar="USER", help="username/email for the login macro")
    h.add_argument("--login-pass", metavar="PASS", help="password for the login macro")
    h.add_argument("--login-user-field", help="login form username field name (auto-detected if omitted)")
    h.add_argument("--login-pass-field", help="login form password field name (auto-detected if omitted)")
    h.add_argument("--login-success", metavar="TEXT",
                   help="text present in the response only when login succeeded")
    h.add_argument("--login-logged-out", metavar="TEXT",
                   help="text shown when logged out; enables mid-scan session re-auth")
    h.add_argument("--discover", action="store_true",
                   help="content + parameter discovery (wordlist brute-forcing)")
    h.add_argument("--wordlist", metavar="FILE", help="custom content-discovery wordlist")
    h.add_argument("--nuclei", action="store_true",
                   help="also run nuclei against the target (needs the nuclei binary)")
    h.add_argument("--access-control", action="store_true",
                   help="run access-control checks (auth-vs-anonymous; IDOR with a second identity)")
    h.add_argument("--idor-cookie", action="append", default=[], metavar="'name=value'",
                   help="second identity (user B) cookie for IDOR comparison (repeatable)")
    h.add_argument("--idor-header", action="append", default=[], metavar="'Name: Value'",
                   help="second identity (user B) header for IDOR comparison (repeatable)")
    h.add_argument("--port-scan", action="store_true",
                   help="include a port-scan recon step (nmap if available, else connect scan)")
    h.add_argument("--ports", metavar="SPEC",
                   help="ports to scan, e.g. '22,80,443,8000-8100' (default: common ports)")
    h.add_argument("--no-nmap", action="store_true",
                   help="force the built-in connect scan even if nmap is installed")
    h.add_argument("--ai-provider", choices=available_providers(),
                   help="enable an AI payload provider")
    h.add_argument("--ai-model", help="model name for the AI provider")
    h.add_argument("--fail-on", choices=[str(x) for x in Severity],
                   help="exit non-zero if any kept finding >= this severity")
    h.add_argument("-v", "--verbose", action="store_true")

    # portscan (standalone recon)
    ps = sub.add_parser("portscan", help="TCP port-scan recon (nmap if available, else connect scan)")
    ps.add_argument("target", help="target host or URL")
    ps.add_argument("--i-am-authorized", action="store_true",
                    help="affirm you have explicit written permission to test the target")
    ps.add_argument("--ports", metavar="SPEC",
                    help="ports to scan, e.g. '22,80,443,8000-8100' (default: common ports)")
    ps.add_argument("--scope", nargs="*", default=[], metavar="HOST",
                    help="additional in-scope hosts/wildcards")
    ps.add_argument("--allow-private", action="store_true",
                    help="permit private/internal addresses (dangerous)")
    ps.add_argument("--no-nmap", action="store_true", help="force the built-in connect scan")
    ps.add_argument("--timeout", type=float, default=1.5, help="per-port connect timeout (connect scan)")
    ps.add_argument("--format", default="table", choices=["table", "json"], help="output format")

    # brain
    b = sub.add_parser("brain", help="inspect the persistent scan memory")
    b.add_argument("action", choices=["stats"], help="what to show")
    b.add_argument("target", help="target URL to report on")
    b.add_argument("--brain", default=".panoptes/brain.db", help="path to the brain database")

    # plugins
    sub.add_parser("plugins", help="list available check plugins")
    # providers
    sub.add_parser("providers", help="list available AI providers")
    # payloads
    sub.add_parser("payloads", help="list payload library vuln classes")
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
    if getattr(args, "render", False):
        cfg.crawl.render = True
    if getattr(args, "stored_xss", False):
        cfg.stored_xss = True
    if getattr(args, "auth_ratelimit", False):
        cfg.auth_ratelimit = True
    if getattr(args, "verify_xss", False):
        cfg.verify_xss = True
    if getattr(args, "ai_report", False):
        cfg.ai_report = True
    if getattr(args, "ssrf_oob", False):
        cfg.oob.enabled = True
    if getattr(args, "oob_host", None):
        cfg.oob.host = args.oob_host
    if getattr(args, "oob_port", None):
        cfg.oob.port = args.oob_port
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

    # Login macro (hunt only).
    if getattr(args, "login_url", None):
        cfg.login.url = args.login_url
        cfg.login.username = getattr(args, "login_user", "") or ""
        cfg.login.password = getattr(args, "login_pass", "") or ""
        if getattr(args, "login_user_field", None):
            cfg.login.username_field = args.login_user_field
        if getattr(args, "login_pass_field", None):
            cfg.login.password_field = args.login_pass_field
        if getattr(args, "login_success", None):
            cfg.login.success_indicator = args.login_success
        if getattr(args, "login_logged_out", None):
            cfg.login.logged_out_indicator = args.login_logged_out

    # Discovery / nuclei (hunt only).
    if getattr(args, "discover", False):
        cfg.discovery.enabled = True
    if getattr(args, "wordlist", None):
        cfg.discovery.wordlist = args.wordlist
    if getattr(args, "nuclei", False):
        cfg.nuclei.enabled = True

    # Access-control / IDOR (hunt only).
    if getattr(args, "access_control", False):
        cfg.access.enabled = True
    for raw in getattr(args, "idor_header", None) or []:
        name, sep, value = raw.partition(":")
        if sep and name.strip():
            cfg.access.idor_headers[name.strip()] = value.strip()
    for raw in getattr(args, "idor_cookie", None) or []:
        for part in raw.split(";"):
            n, sep, v = part.partition("=")
            if sep and n.strip():
                cfg.access.idor_cookies[n.strip()] = v.strip()

    # Port-scan options (hunt only).
    if getattr(args, "port_scan", False):
        cfg.portscan.enabled = True
    if getattr(args, "ports", None):
        cfg.portscan.ports = parse_ports(args.ports)
    if getattr(args, "no_nmap", False):
        cfg.portscan.use_nmap = False

    # Authenticated-scan credentials.
    for raw in getattr(args, "header", None) or []:
        name, sep, value = raw.partition(":")
        if not sep:
            print(f"warning: ignoring malformed --header {raw!r} (expected 'Name: Value')",
                  file=sys.stderr)
            continue
        if name.strip():
            cfg.auth.headers[name.strip()] = value.strip()
    for raw in getattr(args, "cookie", None) or []:
        for part in raw.split(";"):
            n, sep, v = part.partition("=")
            if not sep:
                continue
            if n.strip():
                cfg.auth.cookies[n.strip()] = v.strip()
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
        _print_auth(cfg)

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


def _cmd_hunt(args: argparse.Namespace) -> int:
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
        print(f"[*] hunting: {cfg.target}  scope={scope.allow}", file=sys.stderr)
        _print_auth(cfg)

    try:
        scope.require_authorization()
    except AuthorizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    brain = None if args.no_brain else Brain(args.brain)
    try:
        import asyncio

        hunt = asyncio.run(Hunt(cfg, scope, brain=brain, strict=args.strict).run())
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:  # pragma: no cover
        print("aborted", file=sys.stderr)
        return 130
    finally:
        if brain is not None:
            brain.close()

    report = render_hunt(hunt, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[+] wrote {args.format} hunt report to {args.output}", file=sys.stderr)
        if hunt.validation:
            s = hunt.validation.summary()
            print(
                f"[+] confirmed={s['confirmed']} needs-review={s['needs_review']} "
                f"dropped-fp={s['likely_fp']} chains={len(hunt.chains)}",
                file=sys.stderr,
            )
    else:
        print(report)

    if args.fail_on:
        threshold = Severity.from_name(args.fail_on)
        if any(f.severity >= threshold for f in hunt.findings):
            return 1
    return 0


def _cmd_portscan(args: argparse.Namespace) -> int:
    from urllib.parse import urlsplit

    raw = args.target
    host = urlsplit(raw).hostname or raw
    allow = list(dict.fromkeys([host] + list(args.scope)))
    scope = Scope(allow=allow, allow_private=args.allow_private, authorized=args.i_am_authorized)
    if not args.i_am_authorized:
        print(
            "error: port scanning requires --i-am-authorized (explicit permission to test).",
            file=sys.stderr,
        )
        return 3

    ports = parse_ports(args.ports) if args.ports else None
    scanner = PortScanner(scope, timeout=args.timeout, use_nmap=not args.no_nmap)
    try:
        import asyncio

        result = asyncio.run(scanner.scan(host, ports))
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        import json

        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(f"# Port scan ({result.method}) — {result.host}")
    if not result.open_ports:
        print("  no common ports open")
    for op in result.open_ports:
        banner = f"  {op.banner}" if op.banner else ""
        print(f"  {op.port:>5}/tcp  open   {op.service}{banner}")
    for e in result.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0


def _cmd_brain(args: argparse.Namespace) -> int:
    brain = Brain(args.brain)
    try:
        if args.action == "stats":
            s = brain.stats(args.target)
            print(f"brain: {args.brain}")
            print(f"target: {args.target}")
            print(f"  runs: {s.pop('runs', 0)}")
            for sev in ("critical", "high", "medium", "low", "info"):
                print(f"  {sev:9s}: {s.get(sev, 0)} open")
    finally:
        brain.close()
    return 0


def _cmd_payloads(_args: argparse.Namespace) -> int:
    for vt in vuln_types():
        print(f"  {vt}")
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


def _print_auth(cfg: Config) -> None:
    if cfg.auth.active:
        # Redacted: names only, never values.
        hdrs = ", ".join(sorted(cfg.auth.headers)) or "-"
        cooks = ", ".join(sorted(cfg.auth.cookies)) or "-"
        print(
            f"[*] authenticated: headers=[{hdrs}] cookies=[{cooks}] "
            "(bound to target host)",
            file=sys.stderr,
        )
    if cfg.login.active:
        print(f"[*] login macro: {cfg.login.url} as {cfg.login.username} (password redacted)",
              file=sys.stderr)
    if cfg.access.enabled:
        extra = " + user-B IDOR" if cfg.access.has_second_identity else ""
        print(f"[*] access-control checks enabled{extra}", file=sys.stderr)


def _host_list(target: str) -> List[str]:
    from urllib.parse import urlsplit

    host = urlsplit(target).hostname
    return [host] if host else []


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "hunt":
        return _cmd_hunt(args)
    if args.command == "portscan":
        return _cmd_portscan(args)
    if args.command == "brain":
        return _cmd_brain(args)
    if args.command == "plugins":
        return _cmd_plugins(args)
    if args.command == "providers":
        return _cmd_providers(args)
    if args.command == "payloads":
        return _cmd_payloads(args)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
