from panoptes.models import Finding, Severity
from panoptes.portscan import OpenPort, PortScanResult
from panoptes.recommend import recommend


def _f(plugin):
    return Finding(plugin=plugin, title="t", severity=Severity.HIGH, description="d",
                   url="https://example.com/")


def test_recommends_from_xss_finding():
    recs = recommend([_f("reflected-xss")])
    titles = [r.title for r in recs]
    assert any("reflected XSS" in t for t in titles)


def test_recommends_exposed_datastore_from_ports():
    ports = PortScanResult(host="h", method="connect",
                           open_ports=[OpenPort(port=6379, service="redis")])
    recs = recommend([], ports)
    assert any("redis" in r.title.lower() for r in recs)
    # exposed datastore is high priority and sorts near the top
    assert recs[0].priority >= Severity.HIGH


def test_general_recommendations_always_present():
    recs = recommend([])
    titles = " ".join(r.title for r in recs)
    assert "subdomain" in titles.lower() or "Enumerate subdomains" in titles


def test_sorted_by_priority_desc():
    recs = recommend([_f("security-headers")])
    prios = [int(r.priority) for r in recs]
    assert prios == sorted(prios, reverse=True)


def test_no_duplicate_titles():
    recs = recommend([_f("reflected-xss"), _f("reflected-xss")])
    titles = [r.title for r in recs]
    assert len(titles) == len(set(titles))
