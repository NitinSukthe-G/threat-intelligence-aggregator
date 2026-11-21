"""Parsers for plain-text style feeds (one record per line)."""

import ipaddress

from core.validator import (
    detect_ioc_type, is_valid_cidr, is_valid_domain, is_valid_hash,
    is_valid_ip, is_valid_url, refang,
)


def _lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            line = raw.strip()
            if line and not line.startswith(("#", ";", "//")):
                yield line


def _record(value, ioc_type, feed, **extra):
    record = {
        "indicator": value,
        "type": ioc_type,
        "source": feed.name,
        "category": feed.category,
        "confidence": feed.confidence,
    }
    record.update(extra)
    return record


def parse_ip_lines(path, feed):
    results = []
    for line in _lines(path):
        token = refang(line.split()[0].split(";")[0].split("#")[0])
        if is_valid_ip(token):
            results.append(_record(token, "IP", feed))
    return results


def parse_ipsum(path, feed):
    """IPsum: 'ip<TAB>number_of_blacklists'. Confidence scales with the count."""
    minimum = dict(feed.options).get("min_lists", 3)
    results = []
    for line in _lines(path):
        parts = line.split()
        if len(parts) < 2 or not is_valid_ip(parts[0]):
            continue
        try:
            lists = int(parts[1])
        except ValueError:
            continue
        if lists < minimum:
            continue
        confidence = min(95, feed.confidence + (lists - minimum) * 5)
        results.append(_record(parts[0], "IP", feed, confidence=confidence,
                               tags=[f"{lists}-blacklists"]))
    return results


def parse_url_lines(path, feed):
    results = []
    for line in _lines(path):
        token = refang(line.split()[0])
        if is_valid_url(token):
            results.append(_record(token, "URL", feed))
    return results


def parse_domain_lines(path, feed):
    results = []
    for line in _lines(path):
        token = refang(line.split()[0]).lower()
        if token.startswith("0.0.0.0") or token.startswith("127.0.0.1"):
            parts = line.split()
            token = parts[1].lower() if len(parts) > 1 else ""
        if is_valid_domain(token):
            results.append(_record(token, "DOMAIN", feed))
    return results


def parse_cidr_lines(path, feed):
    """Spamhaus DROP style: '1.2.3.0/24 ; SBL12345'."""
    results = []
    for line in _lines(path):
        token = line.split(";")[0].strip()
        if is_valid_cidr(token):
            network = ipaddress.ip_network(token, strict=False)
            ref = line.split(";")[1].strip() if ";" in line else ""
            results.append(_record(str(network), "CIDR", feed, reference=ref))
    return results


def parse_hash_semicolon(path, feed):
    """Loki format: 'HASH;comment'."""
    results = []
    for line in _lines(path):
        value, _, comment = line.partition(";")
        value = value.strip().lower()
        hash_type = is_valid_hash(value)
        if hash_type:
            results.append(_record(value, hash_type, feed,
                                   malware=comment.strip()[:80], reference=comment.strip()[:200]))
    return results


def parse_any_lines(path, feed):
    """Fallback: detect the IOC type of the first token on every line."""
    results = []
    for line in _lines(path):
        token = refang(line.split()[0].split(",")[0])
        ioc_type = detect_ioc_type(token)
        if ioc_type != "UNKNOWN":
            results.append(_record(token, ioc_type, feed))
    return results
