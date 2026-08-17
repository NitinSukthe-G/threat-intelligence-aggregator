import json

from core.normalizer import normalize_iocs
from core.correlator import correlate_iocs
from core.risk_scoring import apply_risk_scoring


TEST_FILE = "data/raw/correlation_test.json"


def run_correlation_test():
    """
    Verify that the correlation engine correctly identifies
    indicators appearing in multiple sources.
    """

    print()
    print("=" * 70)
    print("        CORRELATION ENGINE TEST")
    print("=" * 70)

    with open(
        TEST_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        raw_iocs = json.load(file)

    print(
        f"[+] Test records loaded: {len(raw_iocs)}"
    )

    normalized = normalize_iocs(
        raw_iocs
    )

    print(
        f"[+] Unique normalized IOCs: {len(normalized)}"
    )

    correlated = correlate_iocs(
        normalized
    )

    scored = apply_risk_scoring(
        correlated
    )

    print()
    print("CORRELATION RESULTS")
    print("-" * 70)

    for item in scored:

        print()
        print(
            f"IOC: {item['indicator']}"
        )

        print(
            f"Type: {item['type']}"
        )

        print(
            f"Sources: {', '.join(item['sources'])}"
        )

        print(
            f"Source Count: {item['source_count']}"
        )

        print(
            f"Correlation Level: "
            f"{item['correlation_level']}"
        )

        print(
            f"Risk Score: "
            f"{item['risk_score']}"
        )

        print(
            f"Risk Level: "
            f"{item['risk_level']}"
        )

    # -------------------------
    # Assertions
    # -------------------------

    ip_result = next(
        item
        for item in scored
        if item["indicator"] == "192.0.2.10"
    )

    domain_result = next(
        item
        for item in scored
        if item["indicator"] == "example-test.com"
    )

    assert ip_result["source_count"] == 3

    assert (
        ip_result["correlation_level"]
        == "HIGH"
    )

    assert domain_result["source_count"] == 2

    assert (
        domain_result["correlation_level"]
        == "MEDIUM"
    )

    print()
    print("=" * 70)
    print("CORRELATION TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_correlation_test()