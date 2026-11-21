from core.allowlist import allowlist_reason, filter_allowlisted
from core.normalizer import normalize_indicator, normalize_iocs, normalize_url
from core.ranges import apply_range_matches


def test_url_normalization_preserves_path_case():
    assert normalize_url("HTTPS://Example.COM/Path/ABC?Q=1") == "https://example.com/Path/ABC?Q=1"
    assert normalize_url("http://example.com/") == "http://example.com"
    assert normalize_url("http://example.com:80/a") == "http://example.com/a"
    assert normalize_url("http://example.com:8080/a") == "http://example.com:8080/a"


def test_indicator_normalization():
    assert normalize_indicator("EVIL.Com.", "DOMAIN") == "evil.com"
    assert normalize_indicator("ABCDEF" * 5 + "AB", "MD5") == ("abcdef" * 5 + "ab")
    assert normalize_indicator("2001:DB8:0:0:0:0:0:1", "IP") == "2001:db8::1"
    assert normalize_indicator("hxxp://a[.]b/x", "URL") == "http://a.b/x"


def test_duplicates_merge_sources_and_keep_best_metadata():
    records = normalize_iocs([
        {"indicator": "1.2.3.4", "type": "IP", "source": "A", "confidence": 50, "first_seen": "2026-02-01"},
        {"indicator": "1.2.3.4", "type": "IP", "source": "B", "confidence": 90, "malware": "Emotet",
         "first_seen": "2026-01-01"},
        {"indicator": "1.2.3.4", "type": "IP", "source": "A"},
    ])
    assert len(records) == 1
    record = records[0]
    assert record["sources"] == ["A", "B"]
    assert record["confidence"] == 90
    assert record["malware"] == "Emotet"
    assert record["first_seen"] == "2026-01-01"


def test_url_derives_domain_and_ip_hosts():
    records = normalize_iocs([
        {"indicator": "http://evil.example.net/a", "type": "URL", "source": "A", "confidence": 100},
        {"indicator": "http://8.8.4.4/x", "type": "URL", "source": "A"},
    ])
    kinds = {(r["type"], r["indicator"]) for r in records}
    assert ("DOMAIN", "evil.example.net") in kinds
    assert ("IP", "8.8.4.4") in kinds
    domain = next(r for r in records if r["type"] == "DOMAIN")
    assert domain["derived_from"] == ["URL"] and domain["confidence"] == 80


def test_derivation_enables_cross_feed_domain_match():
    records = normalize_iocs([
        {"indicator": "http://evil.example.net/a", "type": "URL", "source": "A"},
        {"indicator": "evil.example.net", "type": "DOMAIN", "source": "B"},
    ])
    domain = next(r for r in records if r["type"] == "DOMAIN")
    assert set(domain["sources"]) == {"A", "B"}


def test_unknown_and_empty_are_dropped():
    assert normalize_iocs([{"indicator": "", "type": "IP"}, {"indicator": "x", "type": "UNKNOWN"}]) == []


def test_allowlist():
    assert allowlist_reason("10.0.0.1", "IP")
    assert allowlist_reason("8.8.8.8", "IP")
    assert allowlist_reason("accounts.google.com", "DOMAIN")
    assert allowlist_reason("pages.dev", "DOMAIN")           # shared platform apex
    assert not allowlist_reason("evil.pages.dev", "DOMAIN")  # abusive subdomain stays
    assert not allowlist_reason("45.33.1.1", "IP")
    assert allowlist_reason("corp.internal-test.org", "DOMAIN", extra_domains=("internal-test.org",))
    kept, dropped = filter_allowlisted([
        {"indicator": "10.1.1.1", "type": "IP"}, {"indicator": "45.9.9.9", "type": "IP"}])
    assert len(kept) == 1 and dropped == {"non-routable IP": 1}


def test_cidr_range_matching():
    records = normalize_iocs([
        {"indicator": "45.9.9.0/24", "type": "CIDR", "source": "Drop", "confidence": 90},
        {"indicator": "45.9.9.77", "type": "IP", "source": "Other"},
        {"indicator": "45.9.10.1", "type": "IP", "source": "Other"},
    ])
    assert apply_range_matches(records) == 1
    inside = next(r for r in records if r["indicator"] == "45.9.9.77")
    outside = next(r for r in records if r["indicator"] == "45.9.10.1")
    assert set(inside["sources"]) == {"Other", "Drop"}
    assert "in-range:45.9.9.0/24" in inside["tags"]
    assert outside["sources"] == ["Other"]
