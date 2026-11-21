"""Explainable, rule-based risk scoring (no ML)."""

from datetime import datetime, timezone

HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 35

HIGH_RISK_CATEGORIES = {
    "malware", "botnet", "c2", "command and control", "ransomware",
    "phishing", "malware-download", "apt", "payload_delivery", "botnet_cc",
}

TYPE_POINTS = {
    "IP": (8, "Network indicator (IP)"),
    "DOMAIN": (8, "Domain indicator"),
    "URL": (12, "Malicious URL indicator"),
    "MD5": (15, "File hash indicator"),
    "SHA1": (15, "File hash indicator"),
    "SHA256": (15, "File hash indicator"),
    "EMAIL": (4, "Email indicator"),
    "CIDR": (10, "Hostile netblock (CIDR)"),
}


def parse_timestamp(value):
    """Best-effort parse of the timestamp formats used by the feeds."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    return None


def severity_for(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(ioc, source_weights=None, now=None):
    """Return risk_score, risk_level and the list of reasons behind them."""
    source_weights = source_weights or {}
    now = now or datetime.now(timezone.utc)
    score, reasons = 0, []

    independent = ioc.get(
        "independent_count", ioc.get("source_count", len(ioc.get("sources", [])))
    )
    ioc_type = ioc.get("type", "UNKNOWN")
    confidence = ioc.get("confidence", 0) or 0
    category = str(ioc.get("category", "")).lower()

    # 1. Independent corroboration - the dominant factor.
    if independent >= 4:
        score += 60
        reasons.append(f"Confirmed by {independent} independent sources")
    elif independent == 3:
        score += 50
        reasons.append("Confirmed by 3 independent sources")
    elif independent == 2:
        score += 35
        reasons.append("Confirmed by 2 independent sources")
    else:
        score += 10
        reasons.append("Reported by 1 source")

    # 2. Reputation of the best reporting source.
    weights = [source_weights.get(s, 5) for s in ioc.get("sources", [])] or [5]
    best = max(weights)
    score += best
    if best >= 12:
        reasons.append("Reported by a high-fidelity curated feed")

    # 3. IOC type.
    points, text = TYPE_POINTS.get(ioc_type, (0, ""))
    if points:
        score += points
        reasons.append(text)

    # 4. Source-assigned confidence.
    if confidence >= 80:
        score += 10
        reasons.append("High confidence")
    elif confidence >= 50:
        score += 5
        reasons.append("Medium confidence")

    # 5. Threat category.
    if category in HIGH_RISK_CATEGORIES:
        score += 8
        reasons.append("High-risk threat category")

    # 6. Recency and liveness.
    seen = parse_timestamp(ioc.get("last_online")) or parse_timestamp(ioc.get("first_seen"))
    if seen:
        age_days = (now - seen).days
        if age_days <= 7:
            score += 7
            reasons.append("Active within the last 7 days")
        elif age_days <= 30:
            score += 3
            reasons.append("Active within the last 30 days")
        elif age_days > 180:
            score -= 10
            reasons.append("Stale (not seen for over 180 days)")

    status = str(ioc.get("status", "")).lower()
    if status in {"offline", "down", "dead"}:
        score -= 10
        reasons.append("Infrastructure currently offline")
    elif status in {"online", "active", "up"} and category in {"botnet", "c2", "botnet_cc"}:
        score += 10
        reasons.append("Command-and-control confirmed online")

    score = max(0, min(score, 100))
    return {
        "risk_score": score,
        "risk_level": severity_for(score),
        "risk_reasons": reasons,
    }


def apply_risk_scoring(iocs, source_weights=None):
    """Return copies of the IOCs with scoring fields attached."""
    results = []
    for ioc in iocs:
        updated = ioc.copy()
        updated.update(calculate_risk_score(ioc, source_weights))
        results.append(updated)
    return results
