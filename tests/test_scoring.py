from datetime import datetime, timedelta, timezone

from core.risk_scoring import calculate_risk_score, parse_timestamp, severity_for

NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)


def _ioc(**kw):
    base = {"type": "IP", "sources": ["A"], "independent_count": 1, "confidence": 0, "category": ""}
    base.update(kw)
    return base


def test_single_weak_source_is_low():
    assert calculate_risk_score(_ioc(), {"A": 6}, NOW)["risk_level"] == "LOW"


def test_two_independent_sources_reach_medium_or_high():
    r = calculate_risk_score(
        _ioc(independent_count=2, sources=["A", "B"], confidence=70), {"A": 8, "B": 8}, NOW)
    assert r["risk_level"] in {"MEDIUM", "HIGH"} and r["risk_score"] >= 35


def test_three_sources_with_good_signals_is_high():
    r = calculate_risk_score(
        _ioc(independent_count=3, sources=["A", "B", "C"], confidence=85, category="botnet"),
        {"A": 8}, NOW)
    assert r["risk_level"] == "HIGH"


def test_recency_and_status_adjust_score():
    recent = calculate_risk_score(_ioc(last_online=(NOW - timedelta(days=2)).isoformat()), {}, NOW)
    stale = calculate_risk_score(_ioc(last_online=(NOW - timedelta(days=400)).isoformat()), {}, NOW)
    offline = calculate_risk_score(_ioc(status="offline"), {}, NOW)
    online_c2 = calculate_risk_score(_ioc(status="online", category="botnet"), {}, NOW)
    base = calculate_risk_score(_ioc(), {}, NOW)
    assert recent["risk_score"] > base["risk_score"] > stale["risk_score"]
    assert offline["risk_score"] < base["risk_score"]
    assert online_c2["risk_score"] > base["risk_score"]


def test_score_is_clamped_and_explained():
    r = calculate_risk_score(
        _ioc(type="SHA256", independent_count=9, sources=["A"] * 9, confidence=99,
             category="malware", last_online=NOW.isoformat()), {"A": 15}, NOW)
    assert 0 <= r["risk_score"] <= 100
    assert r["risk_reasons"] and all(isinstance(x, str) for x in r["risk_reasons"])


def test_severity_thresholds():
    assert severity_for(60) == "HIGH" and severity_for(59) == "MEDIUM"
    assert severity_for(35) == "MEDIUM" and severity_for(34) == "LOW"


def test_parse_timestamp_formats():
    for value in ("2026-11-21", "2026-11-21 10:00:00", "2026-11-21T10:00:00Z",
                  "2026-11-21T10:00:00.123456+00:00"):
        assert parse_timestamp(value) is not None
    assert parse_timestamp("garbage") is None and parse_timestamp("") is None
