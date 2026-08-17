def correlate_iocs(normalized_iocs):
    """
    Add correlation information to normalized IOCs.
    """

    results = []

    for ioc in normalized_iocs:

        sources = ioc.get("sources", [])

        source_count = len(sources)

        if source_count >= 3:
            correlation_level = "HIGH"

        elif source_count == 2:
            correlation_level = "MEDIUM"

        else:
            correlation_level = "LOW"

        result = ioc.copy()

        result["source_count"] = source_count
        result["correlation_level"] = correlation_level

        results.append(result)

    return results