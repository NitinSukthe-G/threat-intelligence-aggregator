from datetime import datetime


def normalize_indicator(indicator, ioc_type):
    """
    Normalize an individual IOC value.
    """

    indicator = indicator.strip()

    if ioc_type in {
        "DOMAIN",
        "EMAIL"
    }:
        indicator = indicator.lower()

    elif ioc_type == "URL":

        indicator = indicator.lower().rstrip("/")

    elif ioc_type in {
        "MD5",
        "SHA1",
        "SHA256"
    }:

        indicator = indicator.lower()

    elif ioc_type == "IP":

        indicator = indicator.strip()

    return indicator


def normalize_iocs(iocs):
    """
    Normalize IOC records and merge duplicates.

    Information from multiple feeds is preserved.
    """

    normalized = {}

    for ioc in iocs:

        indicator = str(
            ioc.get(
                "indicator",
                ""
            )
        ).strip()

        ioc_type = ioc.get(
            "type",
            "UNKNOWN"
        )

        source = ioc.get(
            "source",
            "Unknown"
        )

        if not indicator:
            continue

        if ioc_type == "UNKNOWN":
            continue

        indicator = normalize_indicator(
            indicator,
            ioc_type
        )

        key = (
            ioc_type,
            indicator
        )

        if key not in normalized:

            normalized[key] = {
                "indicator": indicator,
                "type": ioc_type,
                "sources": [source],

                "first_seen": ioc.get(
                    "first_seen",
                    datetime.now().isoformat(
                        timespec="seconds"
                    )
                ),

                "last_online": ioc.get(
                    "last_online",
                    ""
                ),

                "port": ioc.get(
                    "port",
                    ""
                ),

                "status": ioc.get(
                    "status",
                    ""
                ),

                "malware": ioc.get(
                    "malware",
                    ""
                ),

                "category": ioc.get(
                    "category",
                    ""
                ),

                "confidence": ioc.get(
                    "confidence",
                    0
                ),

                "reference": ioc.get(
                    "reference",
                    ""
                )
            }

        else:

            existing = normalized[key]

            # Add new source if needed.
            if source not in existing["sources"]:
                existing["sources"].append(source)

            # Keep the highest confidence value.
            existing["confidence"] = max(
                existing.get("confidence", 0),
                ioc.get("confidence", 0)
            )

            # Preserve metadata when available.
            if not existing.get("malware"):
                existing["malware"] = ioc.get(
                    "malware",
                    ""
                )

            if not existing.get("category"):
                existing["category"] = ioc.get(
                    "category",
                    ""
                )

            if not existing.get("reference"):
                existing["reference"] = ioc.get(
                    "reference",
                    ""
                )

            if not existing.get("first_seen"):
                existing["first_seen"] = ioc.get(
                    "first_seen",
                    ""
                )

            if not existing.get("last_online"):
                existing["last_online"] = ioc.get(
                    "last_online",
                    ""
                )

    return list(normalized.values())