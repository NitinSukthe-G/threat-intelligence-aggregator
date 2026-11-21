"""Blocklist generation: plain lists plus firewall / DNS / IDS / STIX formats."""

import csv
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

HASH_TYPES = {"MD5", "SHA1", "SHA256"}
CSV_FIELDS = [
    "indicator", "type", "risk_level", "risk_score", "source_count",
    "independent_count", "sources", "category", "malware", "confidence",
    "first_seen", "last_online", "tags", "risk_reasons",
]
_STIX_NS = uuid.UUID("6f1b6c7e-5a3e-4c55-9d52-0a1b2c3d4e5f")

# Output files the dashboard is allowed to serve.
OUTPUT_FILES = [
    "ip_blocklist.txt", "cidr_blocklist.txt", "domain_blocklist.txt",
    "url_blocklist.txt", "hash_blocklist.txt", "email_blocklist.txt",
    "blocklist.csv", "blocklist.json", "ipset_blocklist.rules",
    "hosts_blocklist.txt", "dns_rpz.zone", "suricata_blocklist.rules",
    "stix_bundle.json", "ti_results.json", "run_summary.json",
    "threat_intelligence_report.html",
]


def _unique(values):
    return list(dict.fromkeys(values))


def _write_lines(path, lines, header=None):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        if header:
            handle.write(header.rstrip("\n") + "\n")
        for line in lines:
            handle.write(f"{line}\n")


def _header(title, count, min_score):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (f"# {title}\n# Generated: {stamp}\n# Entries: {count}\n"
            f"# Minimum risk score: {min_score}\n# Source: Threat Intelligence Aggregator")


def select(iocs, min_score):
    return [i for i in iocs if i.get("risk_score", 0) >= min_score]


def collapse_networks(ips, cidrs):
    """Merge IPs and CIDRs into the smallest covering list of networks."""
    v4, v6 = [], []
    for value in list(ips) + list(cidrs):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        (v4 if network.version == 4 else v6).append(network)
    merged = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return [str(n) for n in merged]


def _ipset_rules(networks):
    v4 = [n for n in networks if ":" not in n]
    v6 = [n for n in networks if ":" in n]
    lines = ["# Load with: ipset restore -exist < ipset_blocklist.rules",
             "# Then:      iptables -I INPUT -m set --match-set tia-block4 src -j DROP"]
    for name, family, items in (("tia-block4", "inet", v4), ("tia-block6", "inet6", v6)):
        if not items:
            continue
        lines.append(f"create {name} hash:net family {family} hashsize 4096 "
                     f"maxelem {max(65536, len(items) * 2)} -exist")
        lines.append(f"flush {name}")
        lines.extend(f"add {name} {item} -exist" for item in items)
    return lines


def _suricata_rules(domains, ips):
    rules, sid = [], 9100000
    for domain in domains:
        sid += 1
        rules.append(
            f'alert dns any any -> any any (msg:"TIA malicious domain {domain}"; '
            f'dns.query; content:"{domain}"; nocase; endswith; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)')
    for ip in ips:
        sid += 1
        rules.append(
            f'alert ip any any -> {ip} any (msg:"TIA malicious IP {ip}"; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)')
    return rules


def _stix_pattern(ioc):
    value = ioc["indicator"].replace("\\", "\\\\").replace("'", "\\'")
    kind = ioc["type"]
    if kind == "IP":
        obj = "ipv6-addr" if ":" in ioc["indicator"] else "ipv4-addr"
        return f"[{obj}:value = '{value}']"
    if kind == "CIDR":
        obj = "ipv6-addr" if ":" in ioc["indicator"] else "ipv4-addr"
        return f"[{obj}:value = '{value}']"
    if kind == "DOMAIN":
        return f"[domain-name:value = '{value}']"
    if kind == "URL":
        return f"[url:value = '{value}']"
    if kind == "EMAIL":
        return f"[email-addr:value = '{value}']"
    algo = {"MD5": "MD5", "SHA1": "'SHA-1'", "SHA256": "'SHA-256'"}[kind]
    return f"[file:hashes.{algo} = '{value}']"


def build_stix_bundle(iocs):
    """Export IOCs as a STIX 2.1 bundle of indicators (deterministic ids)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []
    for ioc in iocs:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(_STIX_NS, f"{ioc['type']}:{ioc['indicator']}")),
            "created": now,
            "modified": now,
            "name": f"{ioc['type']} {ioc['indicator']}"[:200],
            "description": "; ".join(ioc.get("risk_reasons", []))[:500],
            "indicator_types": ["malicious-activity"],
            "pattern": _stix_pattern(ioc),
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(ioc.get("confidence", 0) or 0),
            "labels": [str(ioc.get("category") or "malicious"), ioc.get("risk_level", "LOW").lower()],
        })
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}


def _csv_row(ioc):
    row = {field: ioc.get(field, "") for field in CSV_FIELDS}
    row["sources"] = ", ".join(ioc.get("sources", []))
    row["tags"] = ", ".join(ioc.get("tags", []))
    row["risk_reasons"] = "; ".join(ioc.get("risk_reasons", []))
    for field, value in row.items():  # neutralise spreadsheet formula injection
        if isinstance(value, str) and value[:1] in ("=", "+", "-", "@") and field != "indicator":
            row[field] = "'" + value
    return row


def generate_blocklists(iocs, output_dir, min_score=35):
    """Write every blocklist. Returns {'counts': {...}, 'min_score': n, 'files': [...]}."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    chosen = select(iocs, min_score)

    def values(*types):
        return _unique(i["indicator"] for i in chosen if i["type"] in types)

    ips, cidrs = values("IP"), values("CIDR")
    domains, urls = values("DOMAIN"), values("URL")
    hashes, emails = values(*HASH_TYPES), values("EMAIL")
    networks = collapse_networks(ips, cidrs)

    plain = {
        "ip_blocklist.txt": ("IP blocklist", ips),
        "cidr_blocklist.txt": ("CIDR netblock blocklist", cidrs),
        "domain_blocklist.txt": ("Domain blocklist", domains),
        "url_blocklist.txt": ("URL blocklist", urls),
        "hash_blocklist.txt": ("File hash blocklist (MD5/SHA1/SHA256)", hashes),
        "email_blocklist.txt": ("Malicious e-mail blocklist", emails),
    }
    for name, (title, items) in plain.items():
        _write_lines(output_dir / name, items, _header(title, len(items), min_score))

    _write_lines(output_dir / "ipset_blocklist.rules", _ipset_rules(networks))
    _write_lines(output_dir / "hosts_blocklist.txt",
                 (f"0.0.0.0 {d}" for d in domains),
                 _header("hosts-file blocklist", len(domains), min_score))
    _write_lines(output_dir / "dns_rpz.zone",
                 [f"{d} CNAME ." for d in domains] + [f"*.{d} CNAME ." for d in domains],
                 "$TTL 300\n@ SOA localhost. root.localhost. 1 3600 600 86400 300\n@ NS localhost.")
    _write_lines(output_dir / "suricata_blocklist.rules", _suricata_rules(domains, ips),
                 _header("Suricata/Snort rules", len(domains) + len(ips), min_score))

    with open(output_dir / "blocklist.csv", "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(_csv_row(i) for i in chosen)
    (output_dir / "blocklist.json").write_text(
        json.dumps(chosen, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "stix_bundle.json").write_text(
        json.dumps(build_stix_bundle(chosen), indent=2), encoding="utf-8")

    counts = {"ips": len(ips), "cidrs": len(cidrs), "domains": len(domains),
              "urls": len(urls), "hashes": len(hashes), "emails": len(emails)}
    print(f"[+] Blocklists: {counts} (min score {min_score}, "
          f"{len(networks)} firewall networks after collapsing)")
    return {"counts": counts, "min_score": min_score,
            "firewall_networks": len(networks), "selected": len(chosen)}
