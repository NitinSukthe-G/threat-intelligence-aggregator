"""Normalization, de-duplication and relationship derivation."""

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from core.validator import is_public_ip, is_valid_domain, refang

HASH_TYPES = {"MD5", "SHA1", "SHA256"}


def normalize_url(url):
    """Lower-case scheme and host only; paths and queries are case-sensitive."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        if not host:
            return url.strip()
        if ":" in host:
            host = f"[{host}]"
        netloc = host
        if parts.port and parts.port not in (80, 443):
            netloc += f":{parts.port}"
        path = "" if parts.path == "/" else parts.path
        return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))
    except ValueError:
        return url.strip()


def normalize_indicator(indicator, ioc_type):
    indicator = refang(indicator)
    if ioc_type == "DOMAIN":
        return indicator.lower().rstrip(".")
    if ioc_type in HASH_TYPES or ioc_type == "EMAIL":
        return indicator.lower()
    if ioc_type == "URL":
        return normalize_url(indicator)
    if ioc_type == "IP":
        try:
            return str(ipaddress.ip_address(indicator))
        except ValueError:
            return indicator
    return indicator


def _blank_record(indicator, ioc_type, ioc):
    return {
        "indicator": indicator,
        "type": ioc_type,
        "sources": [],
        "first_seen": ioc.get("first_seen") or "",
        "last_online": ioc.get("last_online", ""),
        "port": ioc.get("port", ""),
        "status": ioc.get("status", ""),
        "malware": ioc.get("malware", ""),
        "category": ioc.get("category", ""),
        "confidence": ioc.get("confidence", 0) or 0,
        "reference": ioc.get("reference", ""),
        "tags": [],
        "derived_from": [],
    }


def _merge(existing, ioc, source):
    if source not in existing["sources"]:
        existing["sources"].append(source)
    existing["confidence"] = max(existing["confidence"], ioc.get("confidence", 0) or 0)
    for field in ("malware", "category", "reference", "port", "status"):
        if not existing.get(field) and ioc.get(field):
            existing[field] = ioc[field]
    new_first = ioc.get("first_seen")
    if new_first and (not existing["first_seen"] or str(new_first) < str(existing["first_seen"])):
        existing["first_seen"] = new_first
    new_last = ioc.get("last_online")
    if new_last and str(new_last) > str(existing.get("last_online") or ""):
        existing["last_online"] = new_last
    for tag in ioc.get("tags", []) or []:
        if tag not in existing["tags"]:
            existing["tags"].append(tag)


def derive_host(url):
    """Return (host, type) for the host of a URL, or None."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    if is_public_ip(host):
        return host, "IP"
    if is_valid_domain(host):
        return host.lower(), "DOMAIN"
    return None


def normalize_iocs(iocs, derive=True):
    """
    Normalize, merge duplicates and (optionally) derive host IOCs from URLs.

    A derived domain/IP carries the same source as its URL, so a domain listed
    in feed A that also hosts a URL listed in feed B correlates across feeds.
    """
    normalized = {}

    def add(indicator, ioc_type, ioc, source, derived_from=None):
        key = (ioc_type, indicator)
        record = normalized.get(key)
        if record is None:
            record = normalized[key] = _blank_record(indicator, ioc_type, ioc)
        _merge(record, ioc, source)
        if derived_from and derived_from not in record["derived_from"]:
            record["derived_from"].append(derived_from)

    for ioc in iocs:
        raw = str(ioc.get("indicator", "")).strip()
        ioc_type = ioc.get("type", "UNKNOWN")
        source = ioc.get("source", "Unknown")
        if not raw or ioc_type == "UNKNOWN":
            continue
        indicator = normalize_indicator(raw, ioc_type)
        if not indicator:
            continue
        add(indicator, ioc_type, ioc, source)

        if derive and ioc_type == "URL":
            related = derive_host(indicator)
            if related:
                derived = dict(ioc)
                derived["confidence"] = int((ioc.get("confidence", 0) or 0) * 0.8)
                add(related[0], related[1], derived, source, derived_from="URL")

    return list(normalized.values())
