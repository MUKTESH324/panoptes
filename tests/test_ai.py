from panoptes.ai import NullProvider, PayloadRequest, build_provider
from panoptes.ai.providers import _parse_payloads
from panoptes.ai.registry import FailoverProvider
from panoptes.config import AIConfig


async def test_null_provider_returns_empty():
    out = await NullProvider().generate(PayloadRequest(vuln_type="xss", parameter="q", url="u"))
    assert out == []


def test_build_provider_disabled_is_null():
    assert isinstance(build_provider(AIConfig(enabled=False, provider="openai")), NullProvider)


def test_build_provider_unknown_is_null():
    assert isinstance(build_provider(AIConfig(enabled=True, provider="nope")), NullProvider)


def test_parse_payloads_extracts_json_array():
    text = 'Sure! Here you go:\n["<svg onload=1>", "\' OR 1=1--", 42]'
    out = _parse_payloads(text, limit=10)
    assert "<svg onload=1>" in out
    assert "42" in out


def test_parse_payloads_handles_garbage():
    assert _parse_payloads("no json here", limit=5) == []


async def test_failover_uses_first_nonempty():
    class Empty(NullProvider):
        async def generate(self, request):
            return []

    class Works(NullProvider):
        async def generate(self, request):
            return ["payload"]

    fp = FailoverProvider([Empty(), Works()])
    out = await fp.generate(PayloadRequest(vuln_type="xss", parameter="q", url="u"))
    assert out == ["payload"]


async def test_failover_skips_raising_provider():
    class Boom(NullProvider):
        async def generate(self, request):
            raise RuntimeError("down")

    class Works(NullProvider):
        async def generate(self, request):
            return ["ok"]

    fp = FailoverProvider([Boom(), Works()])
    out = await fp.generate(PayloadRequest(vuln_type="sqli", parameter="id", url="u"))
    assert out == ["ok"]
