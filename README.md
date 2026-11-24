<h1 align="center">Panoptes</h1>

<p align="center">
  <strong>AI-assisted web vulnerability scanner for <em>authorized</em> security testing.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/output-JSON%20%7C%20SARIF%20%7C%20HTML%20%7C%20MD-7c3aed" alt="Reports">
</p>

---

Panoptes crawls a target, runs a plugin suite of non-destructive vulnerability
checks, and (optionally) uses an LLM to generate context-aware payloads. It
produces findings you can export to **JSON, SARIF, Markdown, or HTML**.

It has two modes:

- **`panoptes scan`** — the scanner: crawl + plugin checks + report.
- **`panoptes hunt`** — the agentic layer on top: lightweight recon, then it
  **plans** which checks the surface warrants, runs them, **validates** each
  finding to drop likely false positives, **infers exploit chains** (how issues
  compound into something worse), and **remembers** results in a persistent
  "brain" so later runs show only what *changed*.

It is a clean, modern take on the "AI-driven scanner / bug-bounty agent" idea,
built around principles the space often skips: **a hard authorization gate**, **a
strict scope allowlist on every request**, and **an isolated plugin
architecture** that makes new checks a few lines of code.

> ⚠️ **Authorized use only.** Scan systems you own or have explicit written
> permission to test. See [SECURITY.md](SECURITY.md).

## Highlights

- 🔒 **Safety-first** — scans refuse to start without an authorization flag, and
  every outbound request is checked against a host allowlist. Private/loopback
  addresses are blocked by default.
- 🧩 **Plugin architecture** — each check is an isolated plugin; a failing plugin
  never aborts the scan. Ships with header, cookie, CORS, info-disclosure,
  reflected-XSS, error-based SQLi, and open-redirect checks.
- 🧠 **Agentic hunt mode** — an attack **planner** (passive recon → targeted
  active checks), a **validation gate** that scores findings and drops likely
  false positives, **exploit-chain inference**, and a persistent **brain** that
  diffs each run against the last (retest workflow).
- 🔭 **Port-scan recon** — optional TCP port scan (uses **nmap** when installed,
  with a built-in connect-scan fallback), flagging exposed services, plus a
  **recommended-next-steps** engine that turns findings + open ports into a
  prioritized, tool-by-tool checklist.
- 🔐 **Authenticated scanning** — session cookies / headers, bound to the target
  host and kept out of logs and reports.
- 🤖 **Pluggable AI** — optional payload generation via OpenAI-compatible,
  Anthropic, or local **Ollama** models, with automatic failover. Runs fully
  without any API key.
- 🎯 **Payload library** — a structured, data-driven payload set (XSS, SQLi,
  SSTI, LFI, SSRF, open-redirect) with unique per-probe markers.
- 🕸️ **Async engine** — concurrency limits + a token-bucket rate limiter so you
  stay polite and in control.
- 📊 **Real reports** — SARIF for GitHub code scanning / CI, plus
  HackerOne-style Markdown and a self-contained HTML report.
- ✅ **Tested** — 74 unit/integration tests, lint, type-check, and
  CI across Python 3.9–3.12.

## Install

```bash
git clone https://github.com/MUKTESH324/panoptes.git
cd panoptes
python -m venv .venv && source .venv/bin/activate
pip install -e .            # or: pip install -e ".[dev]" for tests/lint
```

## Quick start

```bash
# List what's available
panoptes plugins
panoptes providers

# Scan a target you are authorized to test (Markdown report to stdout)
panoptes scan https://example.com --i-am-authorized

# HTML report to a file, politely rate-limited
panoptes scan https://example.com --i-am-authorized \
    --rps 5 --format html -o reports/example.html

# SARIF for CI, failing the build on any high+ finding
panoptes scan https://example.com --i-am-authorized \
    --format sarif -o panoptes.sarif --fail-on high

# Only run specific checks, broaden scope to subdomains
panoptes scan https://example.com --i-am-authorized \
    --plugins security-headers cookie-flags --scope "*.example.com"

# Enable AI payloads with a local Ollama model (nothing leaves your host)
panoptes scan https://example.com --i-am-authorized --ai-provider ollama --ai-model llama3
```

### Hunt mode (plan → scan → validate → chain → remember)

```bash
# Autonomous hunt: recon, plan, validate findings, infer chains, remember results
panoptes hunt https://example.com --i-am-authorized

# Strict mode drops likely false positives; persist to a chosen brain DB
panoptes hunt https://example.com --i-am-authorized --strict --brain .panoptes/acme.db

# What changed since the last run? Run it again — the report shows new/known/resolved.
panoptes hunt https://example.com --i-am-authorized --brain .panoptes/acme.db

# Inspect the persistent memory for a target
panoptes brain stats https://example.com --brain .panoptes/acme.db

# List the payload library classes
panoptes payloads
```

A hunt report includes the attack plan and rationale, a validation summary
(confirmed / needs-review / dropped false positives), inferred **exploit
chains**, and a **diff** against the previous run.

### Authenticated scanning (behind login)

Pass a session cookie and/or headers so the crawler and every check run as a
logged-in user. Both `scan` and `hunt` accept them:

```bash
# Session cookie (repeatable, or "a=1; b=2" in one flag)
panoptes hunt https://app.example.com --i-am-authorized -b "session=YOUR_SESSION"

# Bearer token / custom headers (repeatable)
panoptes scan https://api.example.com --i-am-authorized -H "Authorization: Bearer YOUR_TOKEN"
```

Safety: cookies are **bound to the target host**, so they are never sent to
another domain (e.g. via a redirect), and credential values are treated as
secrets — never logged or written into reports. You can also set them under an
`auth:` block in the config file. Grab a valid session from your browser's
devtools (Application → Cookies, or a request's `Authorization` header) for an
account you're authorized to use.

### Port scan & recommended next steps

```bash
# Standalone port scan (nmap if installed, else a built-in connect scan)
panoptes portscan example.com --i-am-authorized --ports "22,80,443,3306,6379,8000-8100"

# Fold a port scan into a hunt; the report gains an "Open ports" table and a
# prioritized "Recommended next steps" checklist (XSS PoC, sqlmap, nuclei, ffuf…)
panoptes hunt https://example.com --i-am-authorized --port-scan
```

Port scanning is single-target, scope-enforced, non-aggressive (TCP connect,
`nmap -sT -sV --version-light -T3`), and still gated by `--i-am-authorized`.
Exposed datastores (Redis, MongoDB, Elasticsearch, databases) and risky
services are flagged with appropriate severity. The recommendations are
**advisory** — authorized verification steps to do next, not automated exploits.

Or drive everything from a config file:

```bash
panoptes scan --config config/panoptes.example.yaml --i-am-authorized
```

## How it works

```
         ┌──────────┐   in-scope URLs    ┌───────────┐
 target ─▶  Crawler  ├───────────────────▶  Engine    │
         └────┬─────┘                     └─────┬─────┘
              │ every request                   │ per URL
              ▼ checked against                 ▼
         ┌──────────┐   Scope + auth       ┌───────────┐     ┌──────────────┐
         │  Scoped   │◀────── gate ────────│  Plugins   │◀────│ AI provider  │
         │HTTP client│                     │ (checks)   │     │ (optional)   │
         └──────────┘                      └─────┬─────┘     └──────────────┘
                                                 ▼
                                   Findings ─▶ dedupe ─▶ JSON/SARIF/MD/HTML
```

## Writing a plugin

```python
from panoptes.plugins.base import Plugin, register
from panoptes.models import Severity

@register
class MissingPoweredBy(Plugin):
    name = "example-check"
    description = "Example custom check."
    passive = True

    async def check(self, ctx):
        if ctx.response is not None and "x-powered-by" in ctx.response.headers:
            self._report(
                ctx,
                title="X-Powered-By present",
                severity=Severity.INFO,
                description="Consider removing this header.",
                remediation="Unset X-Powered-By.",
            )
```

Drop it in `src/panoptes/plugins/` and it's auto-discovered.

## Development

```bash
make dev     # install with dev extras
make test    # pytest
make lint    # ruff
make type    # mypy
```

## Docker

```bash
docker compose build
docker compose run --rm panoptes scan https://example.com \
    --i-am-authorized -o reports/example.html --format html
```

## License

MIT © Muktesh Adusumilli — see [LICENSE](LICENSE).
