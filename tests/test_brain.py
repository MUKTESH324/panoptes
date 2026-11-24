from panoptes.brain import Brain
from panoptes.models import Finding, Severity


def _f(title, sev=Severity.MEDIUM, url="https://example.com/a"):
    return Finding(plugin="p", title=title, severity=sev, description="d", url=url)


def test_brain_new_then_known():
    with Brain(":memory:") as brain:
        r1 = brain.start_run("https://example.com")
        diff1 = brain.record("https://example.com", [_f("A"), _f("B", url="https://example.com/b")], r1)
        brain.finish_run(r1, 2)
        assert len(diff1.new) == 2 and len(diff1.known) == 0

        r2 = brain.start_run("https://example.com")
        diff2 = brain.record("https://example.com", [_f("A"), _f("B", url="https://example.com/b")], r2)
        assert len(diff2.new) == 0 and len(diff2.known) == 2


def test_brain_detects_new_and_resolved():
    with Brain(":memory:") as brain:
        r1 = brain.start_run("t")
        brain.record("t", [_f("A"), _f("B", url="https://example.com/b")], r1)
        r2 = brain.start_run("t")
        diff = brain.record("t", [_f("A"), _f("C", url="https://example.com/c")], r2)
        new_titles = {f.title for f in diff.new}
        resolved_titles = {r["title"] for r in diff.resolved}
        assert new_titles == {"C"}
        assert resolved_titles == {"B"}


def test_brain_stats_and_runs():
    with Brain(":memory:") as brain:
        r1 = brain.start_run("t")
        brain.record("t", [_f("A", sev=Severity.HIGH)], r1)
        brain.finish_run(r1, 1)
        stats = brain.stats("t")
        assert stats["high"] == 1
        assert stats["runs"] == 1
