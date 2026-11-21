"""STIX 2.x parser - extracts IOCs from indicator patterns."""

import json
import re

from core.validator import detect_ioc_type

# [ipv4-addr:value = '1.2.3.4']   [file:hashes.'SHA-256' = 'ab..']
_COMPARISON = re.compile(
    r"(?P<obj>[a-z0-9\-]+):(?P<path>[A-Za-z0-9_.'\"\-]+)\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'"
)

_TYPE_MAP = {
    "ipv4-addr": "IP",
    "ipv6-addr": "IP",
    "domain-name": "DOMAIN",
    "url": "URL",
    "email-addr": "EMAIL",
}


def parse_pattern(pattern):
    """Return [(value, ioc_type)] for every comparison in a STIX pattern."""
    found = []
    for match in _COMPARISON.finditer(pattern or ""):
        obj, path = match.group("obj"), match.group("path")
        value = match.group("value").replace("\\'", "'").replace("\\\\", "\\")
        if obj in _TYPE_MAP and path.startswith(("value", "display_name")):
            ioc_type = _TYPE_MAP[obj]
        elif obj == "file" and "hashes" in path:
            ioc_type = detect_ioc_type(value)
        else:
            continue
        if detect_ioc_type(value) != "UNKNOWN":
            found.append((value, ioc_type if ioc_type in _TYPE_MAP.values() else detect_ioc_type(value)))
    return found


def _objects(document):
    if isinstance(document, dict):
        if isinstance(document.get("objects"), list):
            return document["objects"]
        if document.get("type") == "indicator":
            return [document]
    if isinstance(document, list):
        return document
    return []


def looks_like_stix(document):
    if isinstance(document, dict) and document.get("type") == "bundle":
        return True
    return any(
        isinstance(o, dict) and o.get("type") == "indicator" and "pattern" in o
        for o in _objects(document)[:50]
    )


def parse_stix_document(document, source, default_confidence=60, category="malicious"):
    """Convert a decoded STIX bundle/envelope into unified IOC records."""
    results = []
    for obj in _objects(document):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("revoked"):
            continue
        labels = obj.get("labels") or []
        confidence = obj.get("confidence", default_confidence)
        for value, ioc_type in parse_pattern(obj.get("pattern", "")):
            results.append({
                "indicator": value,
                "type": ioc_type,
                "source": source,
                "first_seen": obj.get("valid_from") or obj.get("created", ""),
                "last_online": obj.get("valid_until") or obj.get("modified", ""),
                "category": (labels[0] if labels else category),
                "confidence": confidence if isinstance(confidence, int) else default_confidence,
                "reference": obj.get("name", "")[:200],
                "tags": list(labels),
            })
    return results


def parse_stix_file(file_path, source="STIX", **kwargs):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        document = json.load(handle)
    return parse_stix_document(document, source, **kwargs)


def parse_stix_feed(path, feed):
    return parse_stix_file(path, feed.name, default_confidence=feed.confidence,
                           category=feed.category)
