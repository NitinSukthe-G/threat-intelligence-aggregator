"""Match IP indicators against CIDR netblock feeds (e.g. Spamhaus DROP)."""

import bisect
import ipaddress


def _build_index(cidr_records):
    index = {4: [], 6: []}
    for record in cidr_records:
        try:
            network = ipaddress.ip_network(record["indicator"], strict=False)
        except ValueError:
            continue
        index[network.version].append(
            (int(network.network_address), int(network.broadcast_address), record)
        )
    for entries in index.values():
        entries.sort(key=lambda item: item[0])
    return index


def apply_range_matches(records):
    """
    For every IP record that falls inside a CIDR record, add that CIDR feed's
    sources to the IP (listed-range corroboration) and tag the IP.
    Returns the number of IPs matched.
    """
    cidrs = [r for r in records if r["type"] == "CIDR"]
    if not cidrs:
        return 0
    index = _build_index(cidrs)
    starts = {v: [e[0] for e in entries] for v, entries in index.items()}
    matched = 0

    for record in records:
        if record["type"] != "IP":
            continue
        try:
            address = ipaddress.ip_address(record["indicator"])
        except ValueError:
            continue
        entries = index[address.version]
        position = bisect.bisect_right(starts[address.version], int(address)) - 1
        # Netblocks may nest, so scan a few predecessors.
        for candidate in range(position, max(position - 8, -1), -1):
            start, end, cidr = entries[candidate]
            if start <= int(address) <= end:
                for source in cidr["sources"]:
                    if source not in record["sources"]:
                        record["sources"].append(source)
                tag = f"in-range:{cidr['indicator']}"
                if tag not in record["tags"]:
                    record["tags"].append(tag)
                record["confidence"] = max(record["confidence"], cidr.get("confidence", 0))
                matched += 1
                break
    return matched
