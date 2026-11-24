from panoptes.payloads import get_payloads, new_marker, vuln_types


def test_vuln_types_present():
    types = vuln_types()
    assert "xss" in types and "sqli" in types and "ssrf" in types


def test_marker_substitution():
    out = get_payloads("xss", marker="MARK123")
    assert any("MARK123" in p for p in out)
    assert all("{marker}" not in p for p in out)


def test_unknown_type_empty():
    assert get_payloads("nope") == []


def test_new_marker_unique():
    assert new_marker() != new_marker()
