"""SSTI, path-traversal, command-injection, exposed-files plugins."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from conftest import FakeClient, make_response

from panoptes.plugins.base import ScanContext
from panoptes.plugins.command_injection import CommandInjection
from panoptes.plugins.exposed_files import ExposedFiles
from panoptes.plugins.path_traversal import PathTraversal
from panoptes.plugins.ssti import SstiProbe


def _val(url, param):
    return parse_qs(urlsplit(url).query).get(param, [""])[0]


async def _run(plugin, url, handler, response=None):
    ctx = ScanContext(url=url, client=FakeClient(handler), response=response)
    await plugin.check(ctx)
    return ctx.findings


# -- SSTI ------------------------------------------------------------------

async def test_ssti_detects_evaluated_expression():
    def handler(url, kwargs):
        v = _val(url, "name")
        # Simulate a template engine evaluating the expression AND removing the
        # surrounding delimiters ({{ }}, ${ }, #{ }, <%= %>, { }).
        evaluated = re.sub(r"(\{\{|\$\{|#\{|\{|<%=)\s*1337\*1337\s*(\}\}|\}|%>)",
                           "1787569", v)
        return make_response(url, text="<h1>Hello " + evaluated + "</h1>")

    findings = await _run(SstiProbe(), "https://example.com/?name=x", handler)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-1336"


async def test_ssti_no_finding_when_reflected_literally():
    def handler(url, kwargs):
        return make_response(url, text="Hello " + _val(url, "name"))  # not evaluated

    assert await _run(SstiProbe(), "https://example.com/?name=x", handler) == []


# -- Path traversal --------------------------------------------------------

async def test_path_traversal_detects_passwd():
    def handler(url, kwargs):
        return make_response(url, text="root:x:0:0:root:/root:/bin/bash\n")

    findings = await _run(PathTraversal(), "https://example.com/?file=a.txt", handler)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-22"


async def test_path_traversal_ignores_non_file_params():
    def handler(url, kwargs):
        return make_response(url, text="root:x:0:0:")

    # 'q' is not file-like and its value has no / or .
    assert await _run(PathTraversal(), "https://example.com/?q=hello", handler) == []


# -- Command injection -----------------------------------------------------

async def test_command_injection_detects_executed_echo():
    def handler(url, kwargs):
        v = _val(url, "host")
        # Simulate shell executing $(echo MID) / `echo MID`: strip the wrapper.
        executed = re.sub(r"\$\(echo ([0-9a-f]+)\)|`echo ([0-9a-f]+)`",
                          lambda m: m.group(1) or m.group(2), v)
        return make_response(url, text="ping output for " + executed)

    findings = await _run(CommandInjection(), "https://example.com/?host=127.0.0.1", handler)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"


async def test_command_injection_no_finding_on_reflection():
    def handler(url, kwargs):
        return make_response(url, text="output " + _val(url, "host"))  # reflected, not executed

    assert await _run(CommandInjection(), "https://example.com/?host=1", handler) == []


# -- Exposed files ---------------------------------------------------------

async def test_exposed_files_flags_git_config():
    def handler(url, kwargs):
        if url.endswith("/.git/config"):
            return make_response(url, text="[core]\n\trepositoryformatversion = 0\n")
        return make_response(url, status=404, text="not found")

    findings = await _run(ExposedFiles(), "https://example.com/", handler)
    assert any(".git" in f.title for f in findings)
    assert any(f.severity.name == "HIGH" for f in findings)


async def test_exposed_files_probes_host_once():
    plugin = ExposedFiles()
    calls = {"n": 0}

    def handler(url, kwargs):
        calls["n"] += 1
        return make_response(url, status=404, text="nope")

    ctx1 = ScanContext(url="https://example.com/a", client=FakeClient(handler))
    ctx2 = ScanContext(url="https://example.com/b", client=FakeClient(handler))
    await plugin.check(ctx1)
    first = calls["n"]
    await plugin.check(ctx2)  # same origin -> should not probe again
    assert calls["n"] == first
