import csv

from core.validator import detect_ioc_type


def parse_urlhaus_file(file_path, feed=None):
    """Parse the URLhaus recent-URLs CSV export."""
    name = feed.name if feed else "URLhaus"
    confidence = feed.confidence if feed else 90
    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        lines = (line for line in handle if not line.lstrip().startswith("#"))
        for row in csv.DictReader(lines, skipinitialspace=True):
            row = {str(k).strip('" '): v for k, v in row.items() if k}
            url = str(row.get("url", "")).strip()
            if not url or detect_ioc_type(url) != "URL":
                continue
            tags = [t for t in str(row.get("tags", "")).split(",") if t.strip()]
            results.append({
                "indicator": url,
                "type": "URL",
                "source": name,
                "first_seen": str(row.get("dateadded", "")).strip(),
                "last_online": str(row.get("last_online", "")).strip(),
                "status": str(row.get("url_status", "")).strip().lower(),
                "malware": tags[0].strip() if tags else "",
                "category": "malware",
                "confidence": confidence,
                "reference": str(row.get("urlhaus_link", "")).strip(),
                "tags": [t.strip() for t in tags],
            })
    return results
