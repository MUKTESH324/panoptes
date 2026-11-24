from panoptes.models import Confidence, Finding, Severity
from panoptes.validation import ValidationGate


def _strong():
    return Finding(
        plugin="reflected-xss", title="XSS", severity=Severity.HIGH, description="d",
        url="https://example.com/s?q=1", confidence=Confidence.FIRM,
        cwe="CWE-79", evidence="reflected", remediation="encode output",
    )


def _weak():
    return Finding(
        plugin="security-headers", title="Referrer-Policy header is missing",
        severity=Severity.INFO, description="d", url="https://example.com/",
        confidence=Confidence.TENTATIVE,
    )


def test_strong_finding_confirmed():
    res = ValidationGate().evaluate([_strong()])
    assert len(res.confirmed) == 1
    assert res.verdicts[0].verdict == "confirmed"


def test_weak_finding_is_likely_fp():
    res = ValidationGate().evaluate([_weak()])
    assert len(res.likely_fp) == 1
    assert res.verdicts[0].verdict == "likely-fp"


def test_kept_excludes_fp():
    res = ValidationGate().evaluate([_strong(), _weak()])
    kept = res.kept
    assert _strong().fingerprint in {f.fingerprint for f in kept}
    assert _weak().fingerprint not in {f.fingerprint for f in kept}


def test_summary_counts():
    res = ValidationGate().evaluate([_strong(), _weak()])
    s = res.summary()
    assert s["confirmed"] == 1
    assert s["likely_fp"] == 1
