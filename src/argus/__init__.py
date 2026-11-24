"""Argus — an AI-assisted web vulnerability scanner for authorized security testing.

Argus crawls a target, runs a plugin suite of non-destructive vulnerability
checks, optionally uses an LLM provider to generate context-aware payloads, and
produces findings that can be exported to JSON, SARIF, Markdown and HTML.

Argus is built for *authorized* testing only. Every scan is gated by an explicit
authorization flag and a scope allowlist (see :mod:`argus.scope`).
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
