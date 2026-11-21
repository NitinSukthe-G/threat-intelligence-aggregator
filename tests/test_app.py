import time

import pytest

import app as app_module
import config
import pipeline

MD5 = "5d41402abc4b2a76b9719d911017c592"
RAW = [
    {"indicator": "45.9.9.9", "type": "IP", "source": "Feodo Tracker", "confidence": 90, "category": "botnet",
     "status": "online", "last_online": "2099-01-01", "malware": "Emotet"},
    {"indicator": "45.9.9.9", "type": "IP", "source": "CINS Army", "confidence": 70},
    {"indicator": "45.8.0.0/16", "type": "CIDR", "source": "Spamhaus DROP", "confidence": 90, "category": "botnet"},
    {"indicator": "http://evil.example.net/Login", "type": "URL", "source": "Phishunt", "confidence": 80,
     "category": "phishing", "last_online": "2099-01-01"},
    {"indicator": "http://evil.example.net/Login", "type": "URL", "source": "OpenPhish", "confidence": 80,
     "category": "phishing"},
    {"indicator": MD5, "type": "MD5", "source": "Loki Hash IOCs", "confidence": 85, "category": "malware"},
    {"indicator": "<img src=x onerror=alert(1)>.example.net", "type": "DOMAIN", "source": "Phishunt"},
    {"indicator": "x.example.net", "type": "DOMAIN", "source": "Phishunt", "malware": "<script>alert(1)</script>",
     "confidence": 95, "category": "phishing", "last_online": "2099-01-01"},
]


@pytest.fixture
def client(monkeypatch, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(config, "OUTPUT_DATA_DIR", out)
    monkeypatch.setattr(app_module, "OUTPUT_DIR", out)
    monkeypatch.setattr(config, "ADMIN_TOKEN", "")
    monkeypatch.setattr(config, "RUN_COOLDOWN_SECONDS", 300)
    monkeypatch.setattr(pipeline, "run_pipeline", lambda *a, **k: None)
    app_module._cache.update(mtime=None, iocs=[], index={}, summary={}, feeds=[], summary_mtime=None)
    app_module._state.update(last_error="", last_started=0.0, last_finished=0.0, auto_checked=True)
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


@pytest.fixture
def loaded(client):
    statuses = [{"name": "Feodo Tracker", "description": "d", "kind": "remote", "status": "fresh",
                 "records": 2, "error": "", "types": {"IP": 2}},
                {"name": "URLhaus", "description": "<b>x</b>", "kind": "remote", "status": "skipped",
                 "records": 0, "error": "ABUSECH_AUTH_KEY not configured", "types": {}}]
    pipeline.process(RAW, statuses, log=lambda *_: None, output_dir=config.OUTPUT_DATA_DIR)
    return client


def test_empty_state_renders_without_data(client):
    response = client.get("/")
    assert response.status_code == 200 and b"Building your first intelligence snapshot" in response.data
    assert client.get("/health").get_json()["iocs"] == 0
    assert client.get("/api/iocs").get_json()["total"] == 0


def test_dashboard_renders_with_data(loaded):
    html = loaded.get("/").get_data(as_text=True)
    assert "IOC explorer" in html and "Feed health" in html and "Check an indicator" in html
    assert "45.9.9.9" in html and "ABUSECH_AUTH_KEY not configured" in html


def test_dashboard_escapes_feed_data(loaded):
    html = loaded.get("/?search=example.net&per_page=100").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)" in html or "&lt;img src=x" in html
    assert "<b>x</b>" not in html


def test_dashboard_filters_sorting_pagination(loaded):
    cell = '<td class="ind"><code>'
    url_view = loaded.get("/?type=URL").get_data(as_text=True)
    assert cell + "45.9.9.9" not in url_view and cell + "http://evil.example.net/Login" in url_view
    assert "No indicators match" in loaded.get("/?search=zzzz-nothing").get_data(as_text=True)
    for query in ("?sort=recent", "?sort=sources", "?sort=indicator", "?sort=bogus", "?page=abc", "?page=9999",
                  "?per_page=7", "?per_page=-5", "?min_sources=zzz", "?min_sources=2", "?risk=HIGH", "?type=HASH",
                  "?source=Phishunt", "?type=%00", "?search=%25%27%22"):
        assert loaded.get("/" + query).status_code == 200, query


def test_api_iocs_filtering_and_limits(loaded):
    data = loaded.get("/api/iocs?type=IP").get_json()
    assert data["total"] == 1 and data["results"][0]["indicator"] == "45.9.9.9"
    assert data["results"][0]["independent_count"] == 2
    two = loaded.get("/api/iocs?min_sources=2").get_json()
    assert {r["indicator"] for r in two["results"]} >= {"45.9.9.9", "http://evil.example.net/Login"}
    assert loaded.get("/api/iocs?per_page=1").get_json()["results"].__len__() == 1
    assert loaded.get("/api/iocs?per_page=100000").get_json()["per_page"] == 500
    assert loaded.get("/api/iocs?risk=HIGH&sort=score").get_json()["results"][0]["risk_level"] == "HIGH"


def test_api_csv_export(loaded):
    response = loaded.get("/api/iocs.csv?type=IP")
    assert response.mimetype == "text/csv" and "attachment" in response.headers["Content-Disposition"]
    lines = response.get_data(as_text=True).strip().splitlines()
    assert lines[0].startswith("indicator,type") and len(lines) == 2


def test_lookup_exact_range_and_invalid(loaded):
    hit = loaded.get("/api/lookup?q=45.9.9.9").get_json()
    assert hit["found"] and hit["match"]["risk_level"] in {"HIGH", "MEDIUM"} and hit["type"] == "IP"
    ranged = loaded.get("/api/lookup?q=45.8.1.1").get_json()
    assert ranged["found"] and ranged["match"] is None and ranged["netblocks"][0]["indicator"] == "45.8.0.0/16"
    # case/format variants normalise to the same indicator
    assert loaded.get("/api/lookup?q=HTTP://EVIL.example.NET/Login").get_json()["found"]
    assert loaded.get("/api/lookup?q=" + MD5.upper()).get_json()["found"]
    assert not loaded.get("/api/lookup?q=1.2.3.4").get_json()["found"]
    assert loaded.get("/api/lookup?q=not%20an%20ioc").get_json()["valid"] is False
    assert loaded.get("/api/lookup").status_code == 400
    assert loaded.get("/api/lookup?q=" + "a" * 5000).status_code == 200


def test_edl_feeds(loaded):
    body = loaded.get("/feeds/ip.txt").get_data(as_text=True)
    assert body.strip().splitlines() == ["45.9.9.9"]
    assert loaded.get("/feeds/ip.txt?min_score=100").get_data(as_text=True) == ""
    assert loaded.get("/feeds/cidr.txt").get_data(as_text=True).strip() == "45.8.0.0/16"
    assert MD5 in loaded.get("/feeds/hash.txt").get_data(as_text=True)
    assert loaded.get("/feeds/evil.txt").status_code == 404
    assert loaded.get("/feeds/ip.txt?min_score=zzz").status_code == 200


def test_downloads_are_whitelisted(loaded):
    assert loaded.get("/download/ip_blocklist.txt").status_code == 200
    assert loaded.get("/download/stix_bundle.json").status_code == 200
    for path in ("/download/../config.py", "/download/..%2Fconfig.py", "/download/app.py",
                 "/download/history.json", "/download/%2e%2e/config.py"):
        assert loaded.get(path).status_code == 404, path


def test_report_route(loaded, client):
    assert loaded.get("/report").mimetype == "text/html"
    (config.OUTPUT_DATA_DIR / "threat_intelligence_report.html").unlink()
    assert client.get("/report").status_code == 404


def test_security_headers(loaded):
    headers = loaded.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert loaded.get("/api/status").headers["Cache-Control"] == "no-store"


def test_errors(loaded):
    page = loaded.get("/nope")
    assert page.status_code == 404 and b"Page not found" in page.data
    api = loaded.get("/api/nope")
    assert api.status_code == 404 and api.get_json() == {"error": "Not found"}
    assert loaded.post("/").status_code == 405


# ------------------------------------------------------------------ run endpoint
def test_run_requires_post_and_enforces_cooldown(client, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "_run_in_background", lambda: calls.append(1))
    assert client.get("/api/run").status_code == 405
    assert client.get("/run-pipeline").status_code == 404                # the old open GET trigger is gone
    first = client.post("/api/run")
    assert first.status_code == 202 and first.get_json()["status"] == "started"
    second = client.post("/api/run")
    assert second.status_code == 429 and second.get_json()["retry_after"] > 0
    assert len(calls) == 1


def test_run_token_protection(client, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_TOKEN", "s3cret")
    monkeypatch.setattr(app_module, "_run_in_background", lambda: None)
    assert client.post("/api/run").status_code == 401
    assert client.post("/api/run", headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert client.post("/api/run", headers={"X-Admin-Token": "s3cret"}).status_code == 202
    assert client.get("/api/status").get_json()["token_required"] is True


def test_run_conflict_when_busy(client, monkeypatch):
    monkeypatch.setattr(pipeline, "is_running", lambda: True)
    assert client.post("/api/run").status_code == 409
    assert client.get("/api/status").get_json()["running"] is True


def test_background_run_records_errors(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("explode")
    monkeypatch.setattr(pipeline, "run_pipeline", boom)
    app_module._run_in_background()
    for _ in range(50):
        if app_module._state["last_finished"]:
            break
        time.sleep(0.05)
    assert "explode" in client.get("/api/status").get_json()["last_error"]


def test_auto_refresh_triggers_once_when_data_missing(client, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "_run_in_background", lambda: calls.append(1))
    app_module._state["auto_checked"] = False
    client.get("/")
    client.get("/")
    assert calls == [1]


def test_cache_reloads_when_results_change(loaded):
    assert loaded.get("/health").get_json()["iocs"] > 0
    path = config.OUTPUT_DATA_DIR / "ti_results.json"
    path.write_text("[]", encoding="utf-8")
    import os
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert loaded.get("/health").get_json()["iocs"] == 0
    path.write_text("{corrupt", encoding="utf-8")
    os.utime(path, (time.time() + 10, time.time() + 10))
    assert loaded.get("/api/iocs").get_json()["total"] == 0              # corrupt file degrades gracefully
