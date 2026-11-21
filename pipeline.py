"""Threat Intelligence Aggregator - end-to-end pipeline orchestrator."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import config
from collectors.fetcher import fetch_feed
from core.allowlist import filter_allowlisted
from core.correlator import correlate_iocs
from core.normalizer import derive_host, normalize_indicator, normalize_iocs
from core.ranges import apply_range_matches
from core.risk_scoring import apply_risk_scoring
from feeds import FEEDS, aggregate_map, corroborate_only_names, source_weights
from generators.blocklist import generate_blocklists
from generators.report import generate_threat_report
from parsers import parse_feed, parse_with_feed

_RUN_LOCK = threading.Lock()
HISTORY_LIMIT = 30
TYPE_KEYS = ("IP", "CIDR", "DOMAIN", "URL", "MD5", "SHA1", "SHA256", "EMAIL")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _count_types(iocs):
    counts = {}
    for ioc in iocs:
        counts[ioc["type"]] = counts.get(ioc["type"], 0) + 1
    return counts


def _collect_remote(feed, force):
    """Fetch + parse one remote feed. Never raises; returns (status_dict, iocs)."""
    status = {
        "name": feed.name, "description": feed.description, "kind": "remote",
        "url": feed.url.replace("{key}", "***") if feed.requires_key else feed.url,
        "weight": feed.weight, "status": "failed", "records": 0,
        "error": "", "seconds": 0.0, "bytes": 0, "types": {},
    }
    started = time.time()
    fetched = fetch_feed(feed, config.RAW_DATA_DIR, force=force)
    status.update(status=fetched.status, error=fetched.error, bytes=fetched.size)
    iocs = []
    if fetched.usable:
        try:
            iocs = parse_with_feed(feed, fetched.path)
            status["records"] = len(iocs)
            status["types"] = _count_types(iocs)
        except Exception as error:  # a broken feed must not kill the run
            status.update(status="failed", error=f"parse error: {error}")
    status["seconds"] = round(time.time() - started, 2)
    return status, iocs


def _collect_local(directory, label):
    """Parse every TXT/CSV/JSON(STIX) file in a directory."""
    results = []
    directory = Path(directory)
    if not directory.is_dir():
        return results
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in {".txt", ".csv", ".json"}:
            continue
        name = f"{label}: {path.name}"
        status = {
            "name": name, "description": f"{label} file", "kind": "local",
            "url": str(path.name), "weight": 5, "status": "failed",
            "records": 0, "error": "", "seconds": 0.0,
            "bytes": path.stat().st_size, "types": {},
        }
        started = time.time()
        try:
            iocs = parse_feed(str(path), name)
            status.update(status="fresh", records=len(iocs), types=_count_types(iocs))
        except Exception as error:
            iocs = []
            status["error"] = f"{type(error).__name__}: {error}"
        status["seconds"] = round(time.time() - started, 2)
        results.append((status, iocs))
    return results


def _collect_taxii():
    import os
    url = os.getenv("TAXII_COLLECTION_URL", "").strip()
    if not url:
        return []
    from collectors.taxii import fetch_taxii_objects
    from parsers.stix_parser import parse_stix_document
    name = "TAXII"
    status = {"name": name, "description": "TAXII 2.1 collection", "kind": "taxii",
              "url": url, "weight": 8, "status": "failed", "records": 0,
              "error": "", "seconds": 0.0, "bytes": 0, "types": {}}
    started = time.time()
    try:
        bundle = fetch_taxii_objects(url, os.getenv("TAXII_USER", ""), os.getenv("TAXII_PASSWORD", ""))
        iocs = parse_stix_document(bundle, name)
        status.update(status="fresh", records=len(iocs), types=_count_types(iocs))
    except Exception as error:
        iocs = []
        status["error"] = f"{type(error).__name__}: {error}"
    status["seconds"] = round(time.time() - started, 2)
    return [(status, iocs)]


def collect_all(force=False, feeds=None, include_samples=None, log=print):
    """Collect from every configured source. Returns (feed_statuses, raw_iocs)."""
    feeds = FEEDS if feeds is None else feeds
    include_samples = config.INCLUDE_SAMPLES if include_samples is None else include_samples
    statuses, raw = [], []

    corroborators = corroborate_only_names()
    primary = [f for f in feeds if f.name not in corroborators]
    secondary = [f for f in feeds if f.name in corroborators]

    with ThreadPoolExecutor(max_workers=6) as pool:
        remote = list(pool.map(lambda f: _collect_remote(f, force), primary))

    extra = _collect_local(config.LOCAL_FEEDS_DIR, "Local")
    if include_samples:
        extra += _collect_local(config.SAMPLES_DIR, "Sample")
    extra += _collect_taxii()

    # Corroboration-only feeds are collected last and trimmed immediately to the
    # indicators other feeds already report, which keeps peak memory low.
    if secondary:
        known = _known_keys([i for _, iocs in remote + extra for i in iocs])
        for feed in secondary:
            status, iocs = _collect_remote(feed, force)
            iocs, dropped = _filter_corroborators(iocs, corroborators, known)
            status["unmatched_dropped"] = dropped
            remote.append((status, iocs))

    for status, iocs in remote + extra:
        statuses.append(status)
        raw.extend(iocs)
        icon = {"fresh": "+", "cached": "+", "stale": "~", "skipped": "-", "failed": "!"}.get(
            status["status"], "?")
        detail = status["error"] or f"{status['records']:,} records"
        log(f"[{icon}] {status['name']:<24} {status['status']:<8} {detail}")
    return statuses, raw


def _summarize(scored, statuses, raw_count, dropped, matched, started):
    by_level = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ioc in scored:
        by_level[ioc["risk_level"]] += 1
    correlated = [i for i in scored if i["independent_count"] >= 2]
    return {
        "generated_at": _now(),
        "duration_seconds": round(time.time() - started, 2),
        "feeds_configured": len(statuses),
        "feeds_ok": sum(1 for s in statuses if s["status"] in {"fresh", "cached", "stale"}),
        "feeds_failed": sum(1 for s in statuses if s["status"] == "failed"),
        "feeds_skipped": sum(1 for s in statuses if s["status"] == "skipped"),
        "raw_iocs": raw_count,
        "unique_iocs": len(scored),
        "duplicates_removed": max(0, raw_count - len(scored)),
        "allowlist_dropped": dropped,
        "range_matches": matched,
        "correlated_iocs": len(correlated),
        "max_independent_sources": max((i["independent_count"] for i in scored), default=0),
        "by_risk": by_level,
        "by_type": _count_types(scored),
    }


def _write_json(path, data):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _append_history(summary):
    path = config.OUTPUT_DATA_DIR / "history.json"
    try:
        history = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(history, list):
            history = []
    except (OSError, ValueError):
        history = []
    history.append({k: summary[k] for k in (
        "generated_at", "unique_iocs", "correlated_iocs", "by_risk", "feeds_ok")})
    _write_json(path, history[-HISTORY_LIMIT:])


def _key(ioc):
    return (ioc.get("type"), normalize_indicator(str(ioc.get("indicator", "")), ioc.get("type", "")))


def _known_keys(records):
    """Indicator keys (plus hosts of URLs) reported by the given records."""
    known = set()
    for ioc in records:
        key = _key(ioc)
        known.add(key)
        if key[0] == "URL":
            host = derive_host(key[1])
            if host:
                known.add((host[1], host[0]))
    return known


def _filter_corroborators(records, corroborators, known=None):
    """
    Corroboration-only feeds (huge aggregator lists) never create standalone
    indicators: their records are kept only when another feed reports the same
    indicator or a URL on the same host. Returns (filtered, dropped_count).
    """
    if not corroborators:
        return records, 0
    if known is None:
        known = _known_keys([r for r in records if r.get("source") not in corroborators])
    kept = [r for r in records if r.get("source") not in corroborators or _key(r) in known]
    return kept, len(records) - len(kept)


def process(raw_iocs, statuses=None, log=print, output_dir=None):
    """Everything after collection: normalize -> correlate -> score -> export."""
    started = time.time()
    output_dir = Path(output_dir or config.OUTPUT_DATA_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    statuses = statuses or []

    raw_count = len(raw_iocs) + sum(st.get("unmatched_dropped", 0) for st in statuses)
    raw_iocs, unmatched = _filter_corroborators(raw_iocs, corroborate_only_names())
    normalized = normalize_iocs(raw_iocs)
    kept, dropped = filter_allowlisted(
        normalized, config.EXTRA_ALLOW_DOMAINS, config.EXTRA_ALLOW_IPS)
    del normalized
    unmatched += sum(st.get("unmatched_dropped", 0) for st in statuses)
    if unmatched:
        dropped["corroboration-only, no match"] = unmatched
    matched = apply_range_matches(kept)
    correlated = correlate_iocs(kept, aggregate_map())
    del kept
    scored = apply_risk_scoring(correlated, source_weights())
    del correlated, raw_iocs
    scored.sort(key=lambda i: (-i["risk_score"], -i["independent_count"], i["indicator"]))

    summary = _summarize(scored, statuses, raw_count, dropped, matched, started)
    log(f"[=] raw {summary['raw_iocs']:,} -> unique {summary['unique_iocs']:,} "
        f"| correlated {summary['correlated_iocs']:,} | "
        f"HIGH {summary['by_risk']['HIGH']:,} MEDIUM {summary['by_risk']['MEDIUM']:,} "
        f"LOW {summary['by_risk']['LOW']:,}")

    # Keep every MEDIUM/HIGH indicator but cap stored LOW ones (memory/disk).
    stored = [i for i in scored if i["risk_level"] != "LOW"]
    stored += [i for i in scored if i["risk_level"] == "LOW"][:config.STORE_LOW_CAP]
    summary["stored_iocs"] = len(stored)
    _write_json(output_dir / "ti_results.json", stored)
    blocklist_stats = generate_blocklists(scored, output_dir, config.BLOCKLIST_MIN_SCORE)
    summary["blocklists"] = blocklist_stats
    generate_threat_report(stored, output_dir / "threat_intelligence_report.html",
                           summary=summary, feeds=statuses)
    _write_json(output_dir / "run_summary.json", {"summary": summary, "feeds": statuses})
    return stored, summary


def run_pipeline(force=False, log=print, feeds=None, include_samples=None):
    """Run the full pipeline. Thread-safe: concurrent calls wait for the lock."""
    with _RUN_LOCK:
        log("=" * 64)
        log("  THREAT INTELLIGENCE AGGREGATOR")
        log("=" * 64)
        statuses, raw = collect_all(force, feeds, include_samples, log)
        scored, summary = process(raw, statuses, log)
        _append_history(summary)
        log(f"[=] Pipeline finished in {summary['duration_seconds']}s "
            f"(blocklist entries: {sum(summary['blocklists']['counts'].values()):,})")
        return {"iocs": scored, "summary": summary, "feeds": statuses}


def is_running():
    return _RUN_LOCK.locked()


def _peak_memory_mb():
    """Peak working set in MB (Windows) or max RSS (POSIX); 0 if unavailable."""
    try:
        import resource  # POSIX
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage / 1024 if usage > 10 ** 6 else usage / 1024
    except ImportError:
        pass
    try:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb)
        return counters.PeakWorkingSetSize / (1024 * 1024)
    except Exception:
        return 0.0


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator - collect, correlate, score and export IOCs.")
    parser.add_argument("--force", action="store_true", help="ignore the feed cache and re-download everything")
    parser.add_argument("--samples", action="store_true", help="also load the bundled sample feeds (data/samples)")
    parser.add_argument("--only", nargs="+", metavar="FEED", help="run only the named feeds")
    parser.add_argument("--list-feeds", action="store_true", help="list configured feeds and exit")
    parser.add_argument("--min-score", type=int, help="minimum risk score for blocklist inclusion")
    args = parser.parse_args(argv)

    if args.list_feeds:
        for feed in FEEDS:
            key = f"  [needs {feed.requires_key}]" if feed.requires_key else ""
            print(f"{feed.name:<18} weight={feed.weight:<3} {feed.fmt:<15} {feed.description}{key}")
        return 0
    if args.min_score is not None:
        config.BLOCKLIST_MIN_SCORE = args.min_score

    feeds = FEEDS
    if args.only:
        wanted = {name.lower() for name in args.only}
        feeds = [f for f in FEEDS if f.name.lower() in wanted]
        if not feeds:
            parser.error("no configured feed matches --only; use --list-feeds")

    result = run_pipeline(force=args.force, feeds=feeds, include_samples=args.samples or None)
    peak = _peak_memory_mb()
    if peak:
        print(f"[=] Peak memory: {peak:.0f} MB")
    return 0 if result["summary"]["feeds_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
