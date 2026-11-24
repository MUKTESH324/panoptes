from argus.models import Finding, ScanResult, Severity


def _finding(**kw):
    base = dict(
        plugin="p",
        title="t",
        severity=Severity.HIGH,
        description="d",
        url="https://example.com/a",
    )
    base.update(kw)
    return Finding(**base)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_from_name():
    assert Severity.from_name("high") is Severity.HIGH
    assert Severity.from_name("CRITICAL") is Severity.CRITICAL


def test_fingerprint_stable_and_ignores_evidence():
    a = _finding(evidence="x")
    b = _finding(evidence="y")
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_by_url():
    a = _finding(url="https://example.com/a")
    b = _finding(url="https://example.com/b")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_ignores_trailing_slash_and_case():
    a = _finding(url="https://Example.com/a/")
    b = _finding(url="https://example.com/a")
    assert a.fingerprint == b.fingerprint


def test_finding_to_dict():
    d = _finding().to_dict()
    assert d["severity"] == "high"
    assert d["confidence"] == "firm"
    assert "fingerprint" in d


def test_scan_result_counts_and_dict():
    r = ScanResult(target="https://example.com")
    r.findings = [_finding(severity=Severity.HIGH), _finding(severity=Severity.LOW, title="t2")]
    counts = r.counts_by_severity()
    assert counts["high"] == 1 and counts["low"] == 1
    d = r.to_dict()
    assert d["counts"]["high"] == 1
    assert len(d["findings"]) == 2
