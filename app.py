"""Flask dashboard + REST API for the Threat Intelligence Aggregator."""

import csv
import hmac
import io
import ipaddress
import json
import os
import threading
import time
from urllib.parse import urlencode

from flask import (
    Flask, Response, abort, jsonify, render_template, request, send_from_directory,
)

import config
import pipeline
from core.normalizer import normalize_indicator
from core.validator import detect_ioc_type
from generators.blocklist import CSV_FIELDS, OUTPUT_FILES, _csv_row

OUTPUT_DIR = config.OUTPUT_DATA_DIR
PER_PAGE_CHOICES = (25, 50, 100)
SORTS = {
    "score": lambda i: (-i.get("risk_score", 0), i.get("indicator", "")),
    "sources": lambda i: (-i.get("independent_count", 0), -i.get("risk_score", 0)),
    "recent": lambda i: (str(i.get("last_online") or i.get("first_seen") or ""),),
    "indicator": lambda i: (i.get("indicator", ""),),
}
TYPE_GROUPS = {"HASH": {"MD5", "SHA1", "SHA256"}}

app = Flask(__name__)
app.json.sort_keys = False

_state = {"last_error": "", "last_started": 0.0, "last_finished": 0.0, "auto_checked": False}
_state_lock = threading.Lock()
_cache = {"mtime": None, "iocs": [], "index": {}, "summary": {}, "feeds": [], "summary_mtime": None}


# --------------------------------------------------------------------------
# Data access
# --------------------------------------------------------------------------

def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def load_data():
    """Return cached results, reloading only when the files change."""
    results_path = OUTPUT_DIR / "ti_results.json"
    summary_path = OUTPUT_DIR / "run_summary.json"
    try:
        mtime = results_path.stat().st_mtime
    except OSError:
        mtime = None
    try:
        summary_mtime = summary_path.stat().st_mtime
    except OSError:
        summary_mtime = None

    if mtime != _cache["mtime"]:
        iocs = _read_json(results_path, [])
        iocs = iocs if isinstance(iocs, list) else []
        _cache.update(mtime=mtime, iocs=iocs,
                      index={(i.get("type"), i.get("indicator")): i for i in iocs})
    if summary_mtime != _cache["summary_mtime"]:
        document = _read_json(summary_path, {})
        _cache.update(summary_mtime=summary_mtime,
                      summary=document.get("summary", {}), feeds=document.get("feeds", []))
    return _cache


def age_label():
    hours = results_age_hours()
    if hours == float("inf"):
        return ""
    if hours < 1 / 60:
        return "just now"
    if hours < 1:
        return f"{int(hours * 60)} min ago"
    if hours < 48:
        return f"{hours:.1f} h ago"
    return f"{int(hours // 24)} days ago"


def results_age_hours():
    mtime = _cache["mtime"] or 0
    return (time.time() - mtime) / 3600 if mtime else float("inf")


# --------------------------------------------------------------------------
# Pipeline execution (background, cooldown-protected)
# --------------------------------------------------------------------------

def _run_in_background():
    def worker():
        with _state_lock:
            _state["last_started"] = time.time()
            _state["last_error"] = ""
        try:
            pipeline.run_pipeline()
        except Exception as error:  # surfaced via /api/status
            with _state_lock:
                _state["last_error"] = f"{type(error).__name__}: {error}"
        finally:
            with _state_lock:
                _state["last_finished"] = time.time()

    threading.Thread(target=worker, name="pipeline-run", daemon=True).start()


def cooldown_remaining():
    if not _state["last_started"]:
        return 0
    return max(0, int(config.RUN_COOLDOWN_SECONDS - (time.time() - _state["last_started"])))


def maybe_auto_refresh():
    """First request after (re)start: build results if missing or stale."""
    if _state["auto_checked"]:
        return
    _state["auto_checked"] = True
    load_data()
    if not pipeline.is_running() and results_age_hours() > config.STALE_AFTER_HOURS:
        _run_in_background()


# --------------------------------------------------------------------------
# Filtering
# --------------------------------------------------------------------------

def filter_iocs(iocs, args):
    search = args.get("search", "").strip().lower()
    ioc_type = args.get("type", "ALL").upper()
    risk = args.get("risk", "ALL").upper()
    source = args.get("source", "ALL")
    try:
        min_sources = max(1, int(args.get("min_sources", 1)))
    except ValueError:
        min_sources = 1

    allowed_types = TYPE_GROUPS.get(ioc_type, {ioc_type})
    selected = []
    for item in iocs:
        if ioc_type != "ALL" and item.get("type") not in allowed_types:
            continue
        if risk != "ALL" and item.get("risk_level") != risk:
            continue
        if source != "ALL" and source not in item.get("sources", []):
            continue
        if item.get("independent_count", 1) < min_sources:
            continue
        if search:
            haystack = " ".join([
                item.get("indicator", ""), " ".join(item.get("sources", [])),
                item.get("malware", ""), item.get("category", ""),
                " ".join(item.get("tags", [])),
            ]).lower()
            if search not in haystack:
                continue
        selected.append(item)
    selected.sort(key=SORTS.get(args.get("sort", "score"), SORTS["score"]))
    if args.get("sort") == "recent":
        selected.reverse()
    return selected


def _int_arg(name, default, low, high):
    try:
        return min(high, max(low, int(request.args.get(name, default))))
    except ValueError:
        return default


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route("/")
def dashboard():
    maybe_auto_refresh()
    data = load_data()
    summary, feeds = data["summary"], data["feeds"]
    matches = filter_iocs(data["iocs"], request.args)

    per_page = _int_arg("per_page", 25, 10, 100)
    if per_page not in PER_PAGE_CHOICES:
        per_page = 25
    total_pages = max(1, -(-len(matches) // per_page))
    page = min(_int_arg("page", 1, 1, 10 ** 6), total_pages)
    start = (page - 1) * per_page

    def query(**overrides):
        params = {k: v for k, v in request.args.items() if v not in ("", "ALL")}
        params.update(overrides)
        return "?" + urlencode({k: v for k, v in params.items() if v not in ("", None)})

    by_risk = summary.get("by_risk", {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
    by_type = summary.get("by_type", {})
    feed_contrib = sorted(
        ((f["name"], f.get("records", 0), f["status"]) for f in feeds),
        key=lambda row: -row[1])
    top_correlated = sorted(
        (i for i in data["iocs"] if i.get("independent_count", 1) >= 2),
        key=lambda i: (-i["independent_count"], -i["risk_score"]))[:8]
    history = _read_json(OUTPUT_DIR / "history.json", [])
    sources = sorted({s for f in feeds if f["status"] in {"fresh", "cached", "stale"}
                      for s in [f["name"]]})

    return render_template(
        "index.html",
        results=matches[start:start + per_page], total=len(matches),
        page=page, total_pages=total_pages, per_page=per_page,
        start_index=start + 1 if matches else 0, end_index=min(start + per_page, len(matches)),
        summary=summary, feeds=feeds, by_risk=by_risk, by_type=by_type,
        feed_contrib=feed_contrib, top_correlated=top_correlated, history=history[-20:],
        sources=sources, args=request.args, query=query,
        files=[f for f in OUTPUT_FILES if (OUTPUT_DIR / f).exists()],
        running=pipeline.is_running(), cooldown=cooldown_remaining(),
        needs_token=bool(config.ADMIN_TOKEN), has_data=bool(data["iocs"]),
        blocklists=summary.get("blocklists", {}),
        age_label=age_label(),
    )


@app.route("/report")
def report():
    path = OUTPUT_DIR / "threat_intelligence_report.html"
    if not path.exists():
        abort(404)
    return Response(path.read_text(encoding="utf-8"), mimetype="text/html")


@app.route("/download/<filename>")
def download_file(filename):
    if filename not in OUTPUT_FILES or not (OUTPUT_DIR / filename).exists():
        abort(404)
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------

@app.route("/health")
def health():
    data = load_data()
    return jsonify(status="ok", iocs=len(data["iocs"]), running=pipeline.is_running(),
                   data_age_hours=None if results_age_hours() == float("inf")
                   else round(results_age_hours(), 2))


@app.route("/api/status")
def api_status():
    load_data()
    return jsonify(
        running=pipeline.is_running(), cooldown_seconds=cooldown_remaining(),
        last_error=_state["last_error"], generated_at=_cache["summary"].get("generated_at"),
        token_required=bool(config.ADMIN_TOKEN))


@app.route("/api/summary")
def api_summary():
    load_data()
    return jsonify(summary=_cache["summary"], feeds=_cache["feeds"])


@app.route("/api/iocs")
def api_iocs():
    matches = filter_iocs(load_data()["iocs"], request.args)
    per_page = _int_arg("per_page", 50, 1, 500)
    total_pages = max(1, -(-len(matches) // per_page))
    page = min(_int_arg("page", 1, 1, 10 ** 6), total_pages)
    start = (page - 1) * per_page
    return jsonify(total=len(matches), page=page, per_page=per_page,
                   total_pages=total_pages, results=matches[start:start + per_page])


@app.route("/api/iocs.csv")
def api_iocs_csv():
    matches = filter_iocs(load_data()["iocs"], request.args)[:50000]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(_csv_row(i) for i in matches)
    return Response(buffer.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=iocs_filtered.csv"})


@app.route("/api/lookup")
def api_lookup():
    """Check a single indicator against the aggregated intelligence."""
    raw = request.args.get("q", "").strip()[:2048]
    if not raw:
        return jsonify(error="Provide ?q=<indicator>"), 400
    ioc_type = detect_ioc_type(raw)
    if ioc_type == "UNKNOWN":
        return jsonify(query=raw, valid=False, found=False,
                       message="Not a recognised IP, domain, URL, hash or e-mail."), 200
    value = normalize_indicator(raw, ioc_type)
    data = load_data()
    hit = data["index"].get((ioc_type, value))
    range_hits = []
    if ioc_type == "IP":
        address = ipaddress.ip_address(value)
        for item in data["iocs"]:
            if item.get("type") == "CIDR":
                try:
                    if address in ipaddress.ip_network(item["indicator"], strict=False):
                        range_hits.append(item)
                except ValueError:
                    continue
    return jsonify(query=raw, normalized=value, type=ioc_type, valid=True,
                   found=bool(hit or range_hits), match=hit, netblocks=range_hits[:5])


FEED_TYPES = {"ip": {"IP"}, "cidr": {"CIDR"}, "domain": {"DOMAIN"}, "url": {"URL"},
              "hash": {"MD5", "SHA1", "SHA256"}, "email": {"EMAIL"}}


@app.route("/feeds/<kind>.txt")
def live_feed(kind):
    """Plain-text External Dynamic List for firewalls (?min_score=60)."""
    if kind not in FEED_TYPES:
        abort(404)
    min_score = _int_arg("min_score", config.BLOCKLIST_MIN_SCORE, 0, 100)
    seen, lines = set(), []
    for item in load_data()["iocs"]:
        if item.get("type") in FEED_TYPES[kind] and item.get("risk_score", 0) >= min_score \
                and item["indicator"] not in seen:
            seen.add(item["indicator"])
            lines.append(item["indicator"])
    return Response("\n".join(lines) + ("\n" if lines else ""), mimetype="text/plain")


def _authorized():
    if not config.ADMIN_TOKEN:
        return True
    supplied = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(supplied.encode(), config.ADMIN_TOKEN.encode())


@app.route("/api/run", methods=["POST"])
def api_run():
    if not _authorized():
        return jsonify(error="Invalid or missing admin token."), 401
    if pipeline.is_running():
        return jsonify(status="running", message="A pipeline run is already in progress."), 409
    wait = cooldown_remaining()
    if wait:
        return jsonify(status="cooldown", retry_after=wait,
                       message=f"Please wait {wait}s before running again."), 429
    _state["last_started"] = time.time()
    _run_in_background()
    return jsonify(status="started"), 202


# --------------------------------------------------------------------------
# Hardening
# --------------------------------------------------------------------------

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if request.path.startswith("/api/") or request.path == "/health":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Internal server error"), 500
    return render_template("error.html", code=500, message="Something went wrong."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
