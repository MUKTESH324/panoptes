from conftest import make_response

from panoptes.planner import Planner, Signals, recon_signals


def test_plan_passive_first():
    plan = Planner().plan(Signals(has_params=True))
    assert plan.phases[0].name == "recon"
    assert "security-headers" in plan.phases[0].plugins


def test_plan_active_when_params():
    plan = Planner().plan(Signals(has_params=True))
    names = plan.all_plugins
    assert "reflected-xss" in names and "sqli-error" in names


def test_plan_deprioritizes_injection_without_params():
    plan = Planner().plan(Signals(has_params=False))
    names = plan.all_plugins
    assert "reflected-xss" not in names
    assert "cors-misconfig" in names  # still worth a CORS probe


def test_planner_respects_available():
    plan = Planner(available=["security-headers"]).plan(Signals(has_params=True))
    assert plan.all_plugins == ["security-headers"]


def test_recon_signals_detects_tech_params_waf():
    pages = {
        "https://example.com/": make_response(
            "https://example.com/",
            headers={"server": "nginx/1.18.0", "cf-ray": "abc"},
        ),
        "https://example.com/s?q=1": make_response("https://example.com/s?q=1"),
    }
    sig = recon_signals(pages)
    assert sig.has_params is True
    assert sig.waf == "cloudflare"
    assert any("nginx" in t for t in sig.tech)
