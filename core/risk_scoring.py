def calculate_risk_score(ioc):
    """
    Calculate an explainable risk score for an IOC.

    Scoring factors:
    - Number of sources
    - IOC type
    - Confidence
    - Threat category
    """

    score = 0
    reasons = []

    source_count = ioc.get("source_count", len(ioc.get("sources", [])))
    ioc_type = ioc.get("type", "UNKNOWN")
    confidence = ioc.get("confidence", 0)
    category = str(ioc.get("category", "")).lower()

    # Multiple independent sources
    if source_count >= 3:
        score += 50
        reasons.append("Reported by 3 or more sources")

    elif source_count == 2:
        score += 30
        reasons.append("Reported by 2 sources")

    else:
        score += 10
        reasons.append("Reported by 1 source")

    # IOC type weighting
    if ioc_type == "IP":
        score += 10
        reasons.append("Network indicator (IP)")

    elif ioc_type == "URL":
        score += 15
        reasons.append("Malicious URL indicator")

    elif ioc_type in {"MD5", "SHA1", "SHA256"}:
        score += 15
        reasons.append("File hash indicator")

    elif ioc_type == "DOMAIN":
        score += 10
        reasons.append("Domain indicator")

    elif ioc_type == "EMAIL":
        score += 5
        reasons.append("Email indicator")

    # Confidence weighting
    if confidence >= 80:
        score += 20
        reasons.append("High confidence")

    elif confidence >= 50:
        score += 10
        reasons.append("Medium confidence")

    # Threat category weighting
    high_risk_categories = {
        "malware",
        "botnet",
        "c2",
        "command and control",
        "ransomware",
        "phishing",
        "malicious",
    }

    if category in high_risk_categories:
        score += 20
        reasons.append("High-risk threat category")

    # Keep score between 0 and 100
    score = min(score, 100)

    # Convert score to severity
    if score >= 60:
        severity = "HIGH"

    elif score >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "risk_level": severity,
        "risk_reasons": reasons,
    }


def apply_risk_scoring(iocs):
    """
    Apply risk scoring to a list of correlated IOC records.
    """

    results = []

    for ioc in iocs:
        risk = calculate_risk_score(ioc)

        updated_ioc = ioc.copy()
        updated_ioc.update(risk)

        results.append(updated_ioc)

    return results