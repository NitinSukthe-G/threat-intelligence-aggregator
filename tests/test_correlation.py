import json
from pathlib import Path

from core.correlator import correlate_iocs, independent_sources
from core.normalizer import normalize_iocs
from core.risk_scoring import apply_risk_scoring

FIXTURE = Path(__file__).parent / "fixtures" / "correlation_test.json"


def _scored():
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return {i["indicator"]: i for i in apply_risk_scoring(correlate_iocs(normalize_iocs(raw)))}


def test_fixture_correlation_levels():
    scored = _scored()
    ip = scored["192.0.2.10"]
    domain = scored["example-test.com"]
    assert ip["source_count"] == 3 and ip["correlation_level"] == "HIGH"
    assert domain["source_count"] == 2 and domain["correlation_level"] == "MEDIUM"


def test_more_sources_never_lowers_score():
    scored = _scored()
    assert scored["192.0.2.10"]["risk_score"] >= scored["example-test.com"]["risk_score"]


def test_aggregators_are_not_independent_confirmation():
    aggregates = {"Phishing.Army": ["OpenPhish", "Phishunt"]}
    assert independent_sources(["OpenPhish", "Phishing.Army"], aggregates) == {"OpenPhish"}
    assert independent_sources(["Phishing.Army"], aggregates) == {"Phishing.Army"}
    assert len(independent_sources(["OpenPhish", "Phishunt", "Phishing.Army"], aggregates)) == 2


def test_correlate_uses_independent_count():
    rec = {"indicator": "a.com", "type": "DOMAIN", "sources": ["OpenPhish", "Phishing.Army"]}
    out = correlate_iocs([rec], {"Phishing.Army": ["OpenPhish"]})[0]
    assert out["source_count"] == 2 and out["independent_count"] == 1
    assert out["correlation_level"] == "LOW"
