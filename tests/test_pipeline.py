import json
import os
import time
from pathlib import Path

import pytest
import requests

import config
import pipeline
from collectors import fetcher
from collectors.taxii import fetch_taxii_objects
from feeds import FEEDS, FEEDS_BY_NAME, aggregate_map, corroborate_only_names, source_weights

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


# ------------------------------------------------------------------ fakes
class FakeResponse:
    def __init__(self, content=b"1.2.3.4\n", status=200, payload=None):
        self.content, self.status_code, self._payload = content, status, payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _do(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.error:
            raise self.error
        return self.response

    def get(self, url, **kw):
        return self._do("GET", url, **kw)

    def post(self, url, **kw):
        return self._do("POST", url, **kw)


def patch_session(monkeypatch, **kw):
    session = FakeSession(**kw)
    monkeypatch.setattr(fetcher, "_session", lambda: session)
    return session


# ------------------------------------------------------------------ fetcher
def test_fetch_fresh_then_cached(monkeypatch, tmp_path, feed):
    session = patch_session(monkeypatch, response=FakeResponse(b"1.2.3.4\n"))
    f = feed(max_age_hours=6)
    first = fetcher.fetch_feed(f, tmp_path)
    assert first.status == "fresh" and first.usable and first.path.read_bytes() == b"1.2.3.4\n"
    second = fetcher.fetch_feed(f, tmp_path)
    assert second.status == "cached" and len(session.calls) == 1
    forced = fetcher.fetch_feed(f, tmp_path, force=True)
    assert forced.status == "fresh" and len(session.calls) == 2


def test_fetch_expired_cache_is_refreshed(monkeypatch, tmp_path, feed):
    patch_session(monkeypatch, response=FakeResponse(b"9.9.9.9\n"))
    f = feed(max_age_hours=1)
    target = tmp_path / f.filename
    target.write_text("old")
    old = time.time() - 7200
    os.utime(target, (old, old))
    assert fetcher.fetch_feed(f, tmp_path).status == "fresh"
    assert target.read_bytes() == b"9.9.9.9\n"


def test_fetch_failure_falls_back_to_stale_cache(monkeypatch, tmp_path, feed):
    f = feed(max_age_hours=1)
    target = tmp_path / f.filename
    target.write_text("cached-data")
    old = time.time() - 7200
    os.utime(target, (old, old))
    patch_session(monkeypatch, error=requests.ConnectionError("down"))
    result = fetcher.fetch_feed(f, tmp_path)
    assert result.status == "stale" and result.usable and "down" in result.error
    assert target.read_text() == "cached-data"  # last good copy preserved


def test_fetch_failure_without_cache(monkeypatch, tmp_path, feed):
    patch_session(monkeypatch, response=FakeResponse(status=503))
    result = fetcher.fetch_feed(feed(), tmp_path)
    assert result.status == "failed" and not result.usable and "503" in result.error


def test_fetch_empty_response_is_rejected_and_keeps_cache(monkeypatch, tmp_path, feed):
    f = feed(max_age_hours=0)
    (tmp_path / f.filename).write_text("good")
    patch_session(monkeypatch, response=FakeResponse(b"   \n"))
    result = fetcher.fetch_feed(f, tmp_path)
    assert result.status == "stale" and (tmp_path / f.filename).read_text() == "good"


def test_fetch_skips_when_key_missing(monkeypatch, tmp_path, feed):
    monkeypatch.setattr(config, "ABUSECH_AUTH_KEY", "")
    result = fetcher.fetch_feed(feed(requires_key="ABUSECH_AUTH_KEY"), tmp_path)
    assert result.status == "skipped" and "ABUSECH_AUTH_KEY" in result.error


def test_fetch_uses_key_in_url_and_threatfox_post(monkeypatch, tmp_path, feed):
    monkeypatch.setattr(config, "ABUSECH_AUTH_KEY", "SECRET")
    session = patch_session(monkeypatch, response=FakeResponse(b"{}"))
    fetcher.fetch_feed(feed("U", url="https://x/{key}/r.csv", requires_key="ABUSECH_AUTH_KEY"), tmp_path)
    assert session.calls[-1][1] == "https://x/SECRET/r.csv"
    fetcher.fetch_feed(feed("T", fmt="threatfox_json", requires_key="ABUSECH_AUTH_KEY"), tmp_path)
    method, _, kw = session.calls[-1]
    assert method == "POST" and kw["headers"]["Auth-Key"] == "SECRET" and kw["json"]["query"] == "get_iocs"


# ------------------------------------------------------------------ registry
def test_registry_is_consistent():
    names = [f.name for f in FEEDS]
    assert len(names) == len(set(names)) and set(FEEDS_BY_NAME) == set(names)
    assert all(0 <= w <= 15 for w in source_weights().values())
    for aggregator, upstreams in aggregate_map().items():
        assert aggregator in names and all(u in names for u in upstreams)
    assert corroborate_only_names() <= set(names)
    assert len({f.filename for f in FEEDS}) == len(FEEDS)


# ------------------------------------------------------------------ pipeline
@pytest.fixture
def isolated(monkeypatch, tmp_path):
    for attr, name in (("RAW_DATA_DIR", "raw"), ("OUTPUT_DATA_DIR", "out"), ("LOCAL_FEEDS_DIR", "local"),
                       ("SAMPLES_DIR", "samples")):
        directory = tmp_path / name
        directory.mkdir()
        monkeypatch.setattr(config, attr, directory)
    monkeypatch.setattr(config, "INCLUDE_SAMPLES", False)
    return tmp_path


def test_collect_all_survives_failing_feeds(monkeypatch, isolated, feed):
    good, bad, broken = feed("Good"), feed("Bad"), feed("Broken", fmt="url_lines")

    def fake_fetch(f, cache_dir, force=False, **kw):
        if f.name == "Bad":
            return fetcher.FetchResult("failed", error="boom")
        path = Path(cache_dir) / f.filename
        path.write_text("1.2.3.4\n" if f.name == "Good" else "\x00\x00 not a url list")
        return fetcher.FetchResult("fresh", path, path.stat().st_size)

    monkeypatch.setattr(pipeline, "fetch_feed", fake_fetch)
    statuses, raw = pipeline.collect_all(feeds=[good, bad, broken], log=lambda *_: None)
    by_name = {s["name"]: s for s in statuses}
    assert by_name["Good"]["status"] == "fresh" and by_name["Good"]["records"] == 1
    assert by_name["Bad"]["status"] == "failed" and by_name["Bad"]["error"] == "boom"
    assert by_name["Broken"]["records"] == 0
    assert [r["indicator"] for r in raw] == ["1.2.3.4"]


def test_collect_all_parse_exception_is_isolated(monkeypatch, isolated, feed):
    monkeypatch.setattr(pipeline, "fetch_feed", lambda f, d, force=False, **kw: fetcher.FetchResult(
        "fresh", Path(d) / "x", 1))
    monkeypatch.setattr(pipeline, "parse_with_feed", lambda f, p: (_ for _ in ()).throw(RuntimeError("bad parse")))
    statuses, raw = pipeline.collect_all(feeds=[feed()], log=lambda *_: None)
    assert statuses[0]["status"] == "failed" and "bad parse" in statuses[0]["error"] and raw == []


def test_local_and_sample_feeds(monkeypatch, isolated):
    (config.LOCAL_FEEDS_DIR / "mine.txt").write_text("45.9.9.9\nhttp://x.example.net/a\n")
    (config.LOCAL_FEEDS_DIR / "broken.json").write_text("{not json")
    (config.LOCAL_FEEDS_DIR / "ignored.exe").write_text("x")
    for f in SAMPLES.iterdir():
        (config.SAMPLES_DIR / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    statuses, raw = pipeline.collect_all(feeds=[], include_samples=True, log=lambda *_: None)
    names = {s["name"]: s for s in statuses}
    assert names["Local: mine.txt"]["records"] == 2
    assert names["Local: broken.json"]["status"] == "failed"
    assert "Local: ignored.exe" not in names
    assert any(n.startswith("Sample: ") for n in names)


def test_process_end_to_end_with_samples(monkeypatch, isolated):
    for f in SAMPLES.iterdir():
        (config.SAMPLES_DIR / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    statuses, raw = pipeline.collect_all(feeds=[], include_samples=True, log=lambda *_: None)
    scored, summary = pipeline.process(raw, statuses, log=lambda *_: None, output_dir=config.OUTPUT_DATA_DIR)

    by_key = {(i["type"], i["indicator"]): i for i in scored}
    domain = by_key[("DOMAIN", "sample-evil-login.net")]
    assert domain["independent_count"] == 4 and domain["risk_level"] == "HIGH"   # txt+csv+json+stix
    assert ("IP", "192.0.2.10") not in by_key                                    # documentation range filtered
    assert summary["allowlist_dropped"].get("non-routable IP", 0) >= 1
    assert ("DOMAIN", "revoked-sample.net") not in by_key
    assert summary["correlated_iocs"] >= 3 and summary["max_independent_sources"] == 4
    assert summary["by_type"]["SHA256"] == 1

    out = config.OUTPUT_DATA_DIR
    for name in ("ti_results.json", "run_summary.json", "threat_intelligence_report.html",
                 "ip_blocklist.txt", "hash_blocklist.txt", "stix_bundle.json", "hosts_blocklist.txt"):
        assert (out / name).exists(), name
    assert "sample-evil-login.net" in (out / "domain_blocklist.txt").read_text()
    stored = json.loads((out / "ti_results.json").read_text(encoding="utf-8"))
    assert len(stored) == len(scored) and stored[0]["risk_score"] >= stored[-1]["risk_score"]


def test_corroboration_only_feed_never_creates_standalone_iocs(isolated):
    raw = [
        {"indicator": "only-army.example.net", "type": "DOMAIN", "source": "Phishing.Army"},
        {"indicator": "both.example.net", "type": "DOMAIN", "source": "Phishing.Army"},
        {"indicator": "both.example.net", "type": "DOMAIN", "source": "Phishunt", "confidence": 80},
    ]
    scored, summary = pipeline.process(raw, [], log=lambda *_: None, output_dir=config.OUTPUT_DATA_DIR)
    assert {i["indicator"] for i in scored} == {"both.example.net"}
    assert summary["allowlist_dropped"]["corroboration-only, no match"] == 1
    # aggregator confirming its own upstream is NOT independent corroboration
    assert scored[0]["independent_count"] == 1 and set(scored[0]["sources"]) == {"Phishing.Army", "Phishunt"}


def test_low_risk_storage_cap(monkeypatch, isolated):
    monkeypatch.setattr(config, "STORE_LOW_CAP", 3)
    raw = [{"indicator": f"45.9.{i // 250}.{i % 250 + 1}", "type": "IP", "source": "CINS Army",
            "confidence": 10} for i in range(40)]
    scored, summary = pipeline.process(raw, [], log=lambda *_: None, output_dir=config.OUTPUT_DATA_DIR)
    assert summary["unique_iocs"] == 40 and summary["by_risk"]["LOW"] == 40
    assert len(scored) == 3 and summary["stored_iocs"] == 3


def test_run_pipeline_writes_history_and_is_serialised(monkeypatch, isolated, feed):
    monkeypatch.setattr(pipeline, "fetch_feed", lambda f, d, force=False, **kw: _write(f, d, "45.9.9.9\n"))
    result = pipeline.run_pipeline(feeds=[feed("One")], log=lambda *_: None)
    pipeline.run_pipeline(feeds=[feed("One")], log=lambda *_: None)
    history = json.loads((config.OUTPUT_DATA_DIR / "history.json").read_text(encoding="utf-8"))
    assert len(history) == 2 and history[0]["unique_iocs"] == result["summary"]["unique_iocs"] == 1
    assert not pipeline.is_running()


def _write(feed, directory, text):
    path = Path(directory) / feed.filename
    path.write_text(text)
    return fetcher.FetchResult("fresh", path, len(text))


def test_history_is_bounded(monkeypatch, isolated):
    monkeypatch.setattr(pipeline, "HISTORY_LIMIT", 3)
    summary = {"generated_at": "t", "unique_iocs": 1, "correlated_iocs": 0, "by_risk": {}, "feeds_ok": 1}
    for _ in range(6):
        pipeline._append_history(summary)
    path = config.OUTPUT_DATA_DIR / "history.json"
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 3
    path.write_text("{corrupt")
    pipeline._append_history(summary)           # corrupt history must not crash the run
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 1


# ------------------------------------------------------------------ TAXII
def test_taxii_pagination(monkeypatch):
    pages = [
        {"objects": [{"type": "indicator", "id": "1"}], "more": True, "next": "abc"},
        {"objects": [{"type": "indicator", "id": "2"}], "more": False},
    ]
    seen = []

    def fake_get(url, headers=None, auth=None, params=None, timeout=0):
        seen.append((url, params, auth))
        return FakeResponse(payload=pages[len(seen) - 1])

    monkeypatch.setattr("collectors.taxii.requests.get", fake_get)
    bundle = fetch_taxii_objects("https://taxii.example/api/collections/x/", "u", "p")
    assert [o["id"] for o in bundle["objects"]] == ["1", "2"]
    assert seen[1][1] == {"next": "abc"} and seen[0][2] == ("u", "p")
    assert seen[0][0].endswith("/collections/x/objects/")


def test_taxii_wired_into_collection(monkeypatch, isolated):
    monkeypatch.setenv("TAXII_COLLECTION_URL", "https://taxii.example/c/")
    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "pattern": "[domain-name:value = 'taxii-evil.example.net']", "confidence": 70}]}
    monkeypatch.setattr("collectors.taxii.fetch_taxii_objects", lambda *a, **k: bundle)
    statuses, raw = pipeline.collect_all(feeds=[], log=lambda *_: None)
    assert statuses[0]["name"] == "TAXII" and raw[0]["indicator"] == "taxii-evil.example.net"
