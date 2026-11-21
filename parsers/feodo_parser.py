import csv

from core.validator import is_valid_ip


def parse_feodo_file(file_path, feed=None):
    """Parse the abuse.ch Feodo Tracker botnet C2 CSV."""
    name = feed.name if feed else "Feodo Tracker"
    confidence = feed.confidence if feed else 90
    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        lines = (line for line in handle if not line.lstrip().startswith("#"))
        for row in csv.DictReader(lines):
            row = {str(k).strip('" '): v for k, v in row.items() if k}
            ip = str(row.get("dst_ip", "")).strip()
            if not is_valid_ip(ip):
                continue
            results.append({
                "indicator": ip,
                "type": "IP",
                "source": name,
                "first_seen": str(row.get("first_seen_utc", "")).strip(),
                "last_online": str(row.get("last_online", "")).strip(),
                "port": str(row.get("dst_port", "")).strip(),
                "status": str(row.get("c2_status", "")).strip().lower(),
                "malware": str(row.get("malware", "")).strip(),
                "category": "botnet",
                "confidence": confidence,
            })
    return results
