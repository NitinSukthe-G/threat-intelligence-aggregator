import json
from pathlib import Path

import pytest

from parsers import PARSERS, parse_feed, parse_with_feed
from parsers.csv_parser import parse_csv_file
from parsers.feodo_parser import parse_feodo_file
from parsers.json_parser import parse_json_file
from parsers.phishunt_parser import parse_phishunt_file
from parsers.stix_parser import looks_like_stix, parse_pattern, parse_stix_document
from parsers.threatfox_parser import parse_threatfox_feed
from parsers.txt_parser import parse_txt_file
from parsers.urlhaus_parser import parse_urlhaus_file

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
MD5 = "5d41402abc4b2a76b9719d911017c592"
SHA256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def by_type(records):
    out = {}
    for r in records:
        out.setdefault(r["type"], set()).add(r["indicator"])
    return out


# ------------------------------------------------------------------ lines
def test_ip_lines_ignores_comments_and_junk(tmp_path, feed):
    path = write(tmp_path, "a.txt", "# comment\n1.2.3.4\n\nnot-ip\n5.6.7.8 ; note\n2001:db8::1\n")
    result = PARSERS["ip_lines"](path, feed())
    assert [r["indicator"] for r in result] == ["1.2.3.4", "5.6.7.8", "2001:db8::1"]
    assert all(r["source"] == "Test Feed" and r["confidence"] == 70 for r in result)


def test_ipsum_threshold_and_confidence(tmp_path, feed):
    path = write(tmp_path, "i.txt", "# hdr\n1.1.1.1\t2\n2.2.2.2\t3\n3.3.3.3\t8\nbad\tx\n")
    result = PARSERS["ipsum"](path, feed("IPsum", fmt="ipsum", confidence=65, options=(("min_lists", 3),)))
    assert [r["indicator"] for r in result] == ["2.2.2.2", "3.3.3.3"]
    assert result[0]["confidence"] == 65 and result[1]["confidence"] == 90


def test_cidr_lines(tmp_path, feed):
    path = write(tmp_path, "d.txt", "; Spamhaus\n1.10.16.0/20 ; SBL256894\n9.9.9.9 ; not cidr\n")
    result = PARSERS["cidr_lines"](path, feed(fmt="cidr_lines"))
    assert len(result) == 1 and result[0]["type"] == "CIDR"
    assert result[0]["indicator"] == "1.10.16.0/20" and result[0]["reference"] == "SBL256894"


def test_url_and_domain_lines(tmp_path, feed):
    urls = write(tmp_path, "u.txt", "http://a.example.net/x\nftp://no\njunk\n")
    assert [r["indicator"] for r in PARSERS["url_lines"](urls, feed())] == ["http://a.example.net/x"]
    domains = write(tmp_path, "d.txt", "# h\nevil.example.net\n0.0.0.0 hosts-style.example.org\nbad domain\n")
    assert [r["indicator"] for r in PARSERS["domain_lines"](domains, feed())] == [
        "evil.example.net", "hosts-style.example.org"]


def test_hash_semicolon(tmp_path, feed):
    path = write(tmp_path, "h.txt", f"# c\n{MD5.upper()};Evil tool\n{SHA256};Other\nnothash;x\n")
    result = PARSERS["hash_semicolon"](path, feed())
    assert {(r["type"], r["indicator"]) for r in result} == {("MD5", MD5), ("SHA256", SHA256)}
    assert result[0]["malware"] == "Evil tool"


# ------------------------------------------------------------------ named feeds
def test_feodo_parser_handles_quoted_header_and_comments(tmp_path):
    path = write(tmp_path, "f.csv", '# comment\n"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
                 '"2026-01-01 10:00:00","45.9.9.9","443","online","2026-11-20","Emotet"\n'
                 '"2026-01-01 10:00:00","not-an-ip","443","offline","2026-11-20","x"\n')
    result = parse_feodo_file(path)
    assert len(result) == 1
    assert result[0]["status"] == "online" and result[0]["malware"] == "Emotet" and result[0]["confidence"] == 90


def test_phishunt_parser_scales_confidence_and_skips_hosting_ip(tmp_path):
    path = write(tmp_path, "p.csv",
                 "url,domain,company,date,first_seen,ip,malicious_google,malicious_openphish,malicious_phishtank\n"
                 "https://bad.example.net/login,bad.example.net,acme,2026-11-20,2026-11-19,188.114.97.3,false,true,true\n")
    result = parse_phishunt_file(path)
    assert by_type(result) == {"URL": {"https://bad.example.net/login"}, "DOMAIN": {"bad.example.net"}}
    assert result[0]["confidence"] == 70 + 14 and result[0]["reference"] == "acme"


def test_urlhaus_parser(tmp_path):
    path = write(tmp_path, "u.csv", '# hdr\nid,dateadded,url,url_status,last_online,threat,tags,urlhaus_link\n'
                 '1,2026-11-01,http://bad.example.net/x.exe,online,2026-11-02,malware_download,"elf,Mozi",https://urlhaus\n')
    result = parse_urlhaus_file(path)
    assert result[0]["status"] == "online" and result[0]["malware"] == "elf" and "Mozi" in result[0]["tags"]


def test_threatfox_parser(tmp_path, feed):
    doc = {"query_status": "ok", "data": [
        {"ioc": "45.9.9.9:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike",
         "threat_type": "botnet_cc", "confidence_level": 100, "first_seen_utc": "2026-11-01 10:00:00",
         "tags": ["cs"]},
        {"ioc": "evil.example.net", "ioc_type": "domain", "malware": "x", "confidence_level": 75},
        {"ioc": SHA256, "ioc_type": "sha256_hash", "malware": "y"},
        {"ioc": "garbage", "ioc_type": "url"},
    ]}
    path = write(tmp_path, "t.json", json.dumps(doc))
    result = parse_threatfox_feed(path, feed("ThreatFox", fmt="threatfox_json"))
    assert by_type(result) == {"IP": {"45.9.9.9"}, "DOMAIN": {"evil.example.net"}, "SHA256": {SHA256}}
    ip = next(r for r in result if r["type"] == "IP")
    assert ip["port"] == "443" and ip["malware"] == "Cobalt Strike" and ip["confidence"] == 100
    assert parse_threatfox_feed(write(tmp_path, "n.json", '{"query_status":"no_result"}'), feed()) == []


# ------------------------------------------------------------------ generic local files
def test_txt_free_text_with_defanging(tmp_path):
    result = parse_txt_file(SAMPLES / "sample_report.txt", "Sample")
    kinds = by_type(result)
    assert "https://login-secure-update.sample-evil-login.net/verify" in kinds["URL"]
    assert "ops@sample-evil-login.net" in kinds["EMAIL"]
    assert MD5 in kinds["MD5"] and SHA256 in kinds["SHA256"]
    assert "192.0.2.10" in kinds["IP"]


def test_csv_prefers_ioc_columns_and_keeps_metadata():
    result = parse_csv_file(SAMPLES / "sample_feed.csv", "Sample")
    kinds = by_type(result)
    assert "sample-evil-login.net" in kinds["DOMAIN"] and MD5 in kinds["MD5"]
    loader = next(r for r in result if r["indicator"] == MD5)
    assert loader["malware"] == "SampleLoader" and loader["confidence"] == 90
    # the free-text description column must not be mined for IOCs
    assert "not-an-indicator" not in {r["indicator"] for r in result}


def test_csv_without_known_columns_scans_all_cells(tmp_path):
    path = write(tmp_path, "x.csv", "foo,bar\n1.2.3.4,hello\nworld,evil.example.net\n")
    assert {r["indicator"] for r in parse_csv_file(path, "S")} == {"1.2.3.4", "evil.example.net"}


def test_json_generic_and_nested():
    result = parse_json_file(SAMPLES / "sample_feed.json", "Sample")
    assert SHA256 in by_type(result)["SHA256"]
    assert "https://cdn.sample-dropper.org/payload.bin" in by_type(result)["URL"]


def test_json_depth_limit(tmp_path):
    nested = "1.2.3.4"
    for _ in range(40):
        nested = {"k": nested}
    path = write(tmp_path, "deep.json", json.dumps(nested))
    assert parse_json_file(path, "S") == []  # pathological nesting is cut off, not crashed


# ------------------------------------------------------------------ STIX
def test_stix_pattern_extraction():
    assert parse_pattern("[ipv4-addr:value = '1.2.3.4']") == [("1.2.3.4", "IP")]
    assert parse_pattern("[domain-name:value = 'a.example.net']") == [("a.example.net", "DOMAIN")]
    assert parse_pattern("[url:value = 'http://a.example.net/x']") == [("http://a.example.net/x", "URL")]
    both = parse_pattern(f"[file:hashes.MD5 = '{MD5}' OR file:hashes.'SHA-256' = '{SHA256}']")
    assert ("MD5" in {t for _, t in both}) and ("SHA256" in {t for _, t in both})
    assert parse_pattern("[process:name = 'cmd.exe']") == []
    assert parse_pattern("") == [] and parse_pattern(None) == []


def test_stix_bundle_skips_revoked_and_non_indicators():
    result = parse_json_file(SAMPLES / "sample_stix.json", "Sample STIX")
    indicators = {r["indicator"] for r in result}
    assert "sample-evil-login.net" in indicators and MD5 in indicators and SHA256 in indicators
    assert "revoked-sample.net" not in indicators
    domain = next(r for r in result if r["indicator"] == "sample-evil-login.net")
    assert domain["category"] == "phishing" and domain["confidence"] == 85


def test_stix_detection():
    assert looks_like_stix({"type": "bundle", "objects": []})
    assert looks_like_stix({"objects": [{"type": "indicator", "pattern": "[url:value = 'http://a.b']"}]})
    assert not looks_like_stix({"threats": [1, 2]})
    assert parse_stix_document([{"type": "indicator", "pattern": "[ipv4-addr:value = '9.9.9.9']"}], "S")[0]["indicator"] == "9.9.9.9"


# ------------------------------------------------------------------ dispatch
def test_parse_feed_dispatch_and_errors(tmp_path):
    assert parse_feed(str(SAMPLES / "sample_feed.csv"), "S")
    with pytest.raises(ValueError):
        parse_feed(str(tmp_path / "x.xml"), "S")


def test_parse_with_feed_unknown_format(feed, tmp_path):
    with pytest.raises(ValueError):
        parse_with_feed(feed(fmt="nope"), tmp_path / "x")


def test_every_registry_feed_has_a_parser():
    from feeds import FEEDS
    assert all(f.fmt in PARSERS for f in FEEDS)
