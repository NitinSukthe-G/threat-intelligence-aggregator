import csv
import json

from core.risk_scoring import apply_risk_scoring
from generators.blocklist import (
    build_stix_bundle, collapse_networks, generate_blocklists,
)
from generators.report import build_report_html, generate_threat_report
from parsers.stix_parser import parse_stix_document

MD5 = "5d41402abc4b2a76b9719d911017c592"


def rec(indicator, type_, score=70, **kw):
    base = {"indicator": indicator, "type": type_, "sources": ["A", "B"], "source_count": 2,
            "independent_count": 2, "risk_score": score, "risk_level": "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW",
            "confidence": 80, "category": "malware", "malware": "", "tags": [], "risk_reasons": ["why"]}
    base.update(kw)
    return base


DATA = [
    rec("45.9.9.9", "IP"), rec("45.9.9.0/24", "CIDR"), rec("45.9.8.8", "IP", score=20),
    rec("evil.example.net", "DOMAIN"), rec("http://evil.example.net/a?B=1", "URL"),
    rec(MD5, "MD5"), rec("bad@example.org", "EMAIL"), rec("2001:db8::bad", "IP"),
]


def test_collapse_networks_merges_ips_into_cidr():
    nets = collapse_networks(["45.9.9.9", "45.9.9.10"], ["45.9.9.0/24", "1.1.1.0/24"])
    assert "45.9.9.0/24" in nets and "45.9.9.9/32" not in nets and "1.1.1.0/24" in nets


def test_generate_blocklists_files_and_threshold(tmp_path):
    stats = generate_blocklists(DATA, tmp_path, min_score=35)
    assert stats["counts"] == {"ips": 2, "cidrs": 1, "domains": 1, "urls": 1, "hashes": 1, "emails": 1}
    ips = (tmp_path / "ip_blocklist.txt").read_text()
    assert "45.9.9.9" in ips and "45.9.8.8" not in ips          # below threshold excluded
    assert (tmp_path / "hash_blocklist.txt").read_text().count(MD5) == 1
    ipset = (tmp_path / "ipset_blocklist.rules").read_text()
    assert "create tia-block4" in ipset and "create tia-block6" in ipset
    assert "add tia-block4 45.9.9.0/24 -exist" in ipset and "add tia-block4 45.9.9.9/32" not in ipset
    assert "0.0.0.0 evil.example.net" in (tmp_path / "hosts_blocklist.txt").read_text()
    rpz = (tmp_path / "dns_rpz.zone").read_text()
    assert "evil.example.net CNAME ." in rpz and "*.evil.example.net CNAME ." in rpz
    suricata = (tmp_path / "suricata_blocklist.rules").read_text()
    assert 'content:"evil.example.net"' in suricata and "sid:9100001;" in suricata


def test_csv_and_json_exports(tmp_path):
    generate_blocklists(DATA, tmp_path, 35)
    rows = list(csv.DictReader((tmp_path / "blocklist.csv").open(encoding="utf-8")))
    assert {r["indicator"] for r in rows} >= {"45.9.9.9", MD5}
    assert "45.9.8.8" not in {r["indicator"] for r in rows}
    assert len(json.loads((tmp_path / "blocklist.json").read_text(encoding="utf-8"))) == len(rows)


def test_csv_formula_injection_is_neutralised(tmp_path):
    evil = rec("evil.example.net", "DOMAIN", malware="=HYPERLINK(\"http://x\")", category="+cmd")
    generate_blocklists([evil], tmp_path, 35)
    row = next(csv.DictReader((tmp_path / "blocklist.csv").open(encoding="utf-8")))
    assert row["category"].startswith("'+") and row["malware"].startswith("'=")


def test_stix_export_round_trips_through_stix_parser():
    bundle = build_stix_bundle([r for r in DATA if r["type"] != "CIDR"])
    assert bundle["type"] == "bundle" and all(o["spec_version"] == "2.1" for o in bundle["objects"])
    parsed = parse_stix_document(bundle, "roundtrip")
    assert {p["indicator"] for p in parsed} == {r["indicator"] for r in DATA if r["type"] != "CIDR"}
    # ids are deterministic so re-exports do not create duplicates downstream
    again = build_stix_bundle([DATA[0]])["objects"][0]["id"]
    assert again == build_stix_bundle([DATA[0]])["objects"][0]["id"]


def test_stix_pattern_escapes_quotes():
    bundle = build_stix_bundle([rec("http://a.example.net/it's", "URL")])
    assert "it\\'s" in bundle["objects"][0]["pattern"]


def test_report_escapes_hostile_feed_data(tmp_path):
    xss = "<script>alert(1)</script>"
    hostile = [rec(f"http://x.example.net/{xss}", "URL", malware=xss, category=xss, sources=[xss, "B"])]
    feeds = [{"name": xss, "status": "fresh", "records": 1, "description": xss, "error": xss, "types": {xss: 1}}]
    html = build_report_html(hostile, {"by_risk": {"HIGH": 1}, "by_type": {xss: 1},
                                       "allowlist_dropped": {xss: 1}}, feeds)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    path = generate_threat_report(hostile, tmp_path / "r.html", {}, feeds)
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_report_handles_empty_input():
    html = build_report_html([], {}, [])
    assert "Threat Intelligence Report" in html and "No indicators in this category" in html


def test_scoring_then_export_integration(tmp_path):
    raw = [{"indicator": "45.9.9.9", "type": "IP", "sources": ["Feodo Tracker"], "confidence": 90,
            "category": "botnet", "status": "online", "last_online": "2099-01-01",
            "source_count": 1, "independent_count": 1}]
    scored = apply_risk_scoring(raw, {"Feodo Tracker": 15})
    assert scored[0]["risk_level"] in {"MEDIUM", "HIGH"}
    assert generate_blocklists(scored, tmp_path, 35)["counts"]["ips"] == 1
