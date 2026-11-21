"""ThreatFox (abuse.ch) JSON API response parser."""

import json

from core.validator import detect_ioc_type

_TYPE_MAP = {
    "ip:port": "IP", "domain": "DOMAIN", "url": "URL",
    "md5_hash": "MD5", "sha1_hash": "SHA1", "sha256_hash": "SHA256",
}


def parse_threatfox_feed(path, feed):
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        document = json.load(handle)
    if document.get("query_status") != "ok":
        return []

    results = []
    for entry in document.get("data") or []:
        raw = str(entry.get("ioc", "")).strip()
        kind = _TYPE_MAP.get(str(entry.get("ioc_type", "")).lower())
        port = ""
        if kind == "IP" and ":" in raw:
            raw, _, port = raw.rpartition(":")
        if kind is None:
            kind = detect_ioc_type(raw)
        # The declared type must agree with what the value actually is.
        if kind == "UNKNOWN" or detect_ioc_type(raw) != kind:
            continue
        results.append({
            "indicator": raw,
            "type": kind,
            "source": feed.name,
            "first_seen": entry.get("first_seen_utc", ""),
            "last_online": entry.get("last_seen_utc") or "",
            "port": port,
            "malware": entry.get("malware_printable") or entry.get("malware", ""),
            "category": entry.get("threat_type") or feed.category,
            "confidence": int(entry.get("confidence_level") or feed.confidence),
            "reference": entry.get("reference") or "",
            "tags": entry.get("tags") or [],
        })
    return results
