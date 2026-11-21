import csv

from core.validator import detect_ioc_type

# Independent verdict columns published by Phishunt.
_VERDICT_COLUMNS = (
    "malicious_google", "malicious_openphish", "malicious_phishtank",
    "malicious_tweetfeed", "malicious_urlscan",
)


def _text(row, key):
    return str(row.get(key, "") or "").strip()


def parse_phishunt_file(file_path, feed=None):
    """
    Parse Phishunt CSV data into URL and domain IOCs.

    Hosting IPs are intentionally ignored: phishing pages mostly sit behind
    shared CDNs (Cloudflare, AWS...) and blocking those would break the web.
    Confidence is raised for every third-party engine that agrees.
    """
    name = feed.name if feed else "Phishunt"
    base = feed.confidence if feed else 70
    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return results

        for row in reader:
            agree = sum(1 for col in _VERDICT_COLUMNS if _text(row, col).lower() == "true")
            confidence = min(98, base + 7 * agree)
            common = {
                "source": name,
                "first_seen": _text(row, "first_seen"),
                "last_online": _text(row, "date"),
                "category": "phishing",
                "confidence": confidence,
                "reference": _text(row, "company"),
                "tags": [f"{agree}-engines-agree"] if agree else [],
            }

            url = _text(row, "url")
            if url and detect_ioc_type(url) == "URL":
                results.append({"indicator": url, "type": "URL", **common})

            domain = _text(row, "domain")
            if domain and detect_ioc_type(domain) == "DOMAIN":
                results.append({"indicator": domain, "type": "DOMAIN", **common})

    return results
