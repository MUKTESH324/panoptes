<h1 align="center">Argus</h1>

<p align="center">
  <strong>AI-assisted web vulnerability scanner for <em>authorized</em> security testing.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/output-JSON%20%7C%20SARIF%20%7C%20HTML%20%7C%20MD-7c3aed" alt="Reports">
</p>

---

Argus crawls a target, runs a plugin suite of non-destructive vulnerability
checks, and (optionally) uses an LLM to generate context-aware payloads. It
produces findings you can export to **JSON, SARIF, Markdown, or HTML**.

It is a clean, modern take on the "AI-driven scanner" idea, built around three
principles the original space often skips: **a hard authorization gate**, **a
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
- 🤖 **Pluggable AI** — optional payload generation via OpenAI-compatible,
  Anthropic, or local **Ollama** models, with automatic failover. Runs fully
  without any API key.
- 🕸️ **Async engine** — concurrency limits + a token-bucket rate limiter so you
  stay polite and in control.
- 📊 **Real reports** — SARIF for GitHub code scanning / CI, plus
  HackerOne-style Markdown and a self-contained HTML report.
- ✅ **Tested** — unit tests with no network dependency, lint, type-check, and
  CI across Python 3.9–3.12.

## Install

```bash
git clone https://github.com/muktesh/argus.git
cd argus
python -m venv .venv && source .venv/bin/activate
pip install -e .            # or: pip install -e ".[dev]" for tests/lint
```

## Quick start

```bash
# List what's available
argus plugins
argus providers

# Scan a target you are authorized to test (Markdown report to stdout)
argus scan https://example.com --i-am-authorized

# HTML report to a file, politely rate-limited
argus scan https://example.com --i-am-authorized \
    --rps 5 --format html -o reports/example.html

# SARIF for CI, failing the build on any high+ finding
argus scan https://example.com --i-am-authorized \
    --format sarif -o argus.sarif --fail-on high

# Only run specific checks, broaden scope to subdomains
argus scan https://example.com --i-am-authorized \
    --plugins security-headers cookie-flags --scope "*.example.com"

# Enable AI payloads with a local Ollama model (nothing leaves your host)
argus scan https://example.com --i-am-authorized --ai-provider ollama --ai-model llama3
```

Or drive everything from a config file:

```bash
argus scan --config config/argus.example.yaml --i-am-authorized
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
from argus.plugins.base import Plugin, register
from argus.models import Severity

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

Drop it in `src/argus/plugins/` and it's auto-discovered.

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
docker compose run --rm argus scan https://example.com \
    --i-am-authorized -o reports/example.html --format html
```

## License

MIT © Muktesh Adusumilli — see [LICENSE](LICENSE).
