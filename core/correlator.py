"""Cross-feed correlation engine."""


def independent_sources(sources, aggregates=None):
    """
    Return the sources that count as *independent* confirmation.

    ``aggregates`` maps an aggregator feed to the upstream feeds it republishes,
    e.g. {"Phishing.Army": ["OpenPhish", "Phishunt"]}. An aggregator adds no
    independent confirmation when one of its upstreams already reported the
    same indicator, so it is dropped from the count in that case.
    """
    aggregates = aggregates or {}
    present = set(sources)
    kept = set()
    for source in present:
        upstreams = set(aggregates.get(source, ()))
        if upstreams & present:
            continue
        kept.add(source)
    return kept


def correlation_level(count):
    if count >= 3:
        return "HIGH"
    if count == 2:
        return "MEDIUM"
    return "LOW"


def correlate_iocs(normalized_iocs, aggregates=None):
    """Annotate every IOC with source_count / independent_count / level."""
    results = []
    for ioc in normalized_iocs:
        sources = ioc.get("sources", [])
        independent = len(independent_sources(sources, aggregates))
        result = ioc.copy()
        result["source_count"] = len(sources)
        result["independent_count"] = independent
        result["correlation_level"] = correlation_level(independent)
        results.append(result)
    return results
