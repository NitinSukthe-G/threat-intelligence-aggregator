import json

from generators.report import generate_threat_report

from config import RAW_DATA_DIR, OUTPUT_DATA_DIR

from collectors.feodo import download_feodo_feed
from collectors.phishunt import download_phishunt_feed

from parsers.feodo_parser import parse_feodo_file
from parsers.phishunt_parser import parse_phishunt_file

from core.normalizer import normalize_iocs
from core.correlator import correlate_iocs
from core.risk_scoring import apply_risk_scoring

from generators.blocklist import generate_blocklists


def collect_feodo():
    """
    Download and parse Feodo Tracker.
    """

    feed_path = RAW_DATA_DIR / "feodo.csv"

    print()
    print("[FEED] Feodo Tracker")

    if not feed_path.exists():

        print("[+] Downloading Feodo feed...")

        success = download_feodo_feed(
            str(feed_path)
        )

        if not success:
            print("[-] Feodo download failed.")
            return []

    if not feed_path.exists():

        print("[-] Feodo feed unavailable.")

        return []

    try:

        data = parse_feodo_file(
            str(feed_path)
        )

        print(
            f"[+] Feodo records: {len(data)}"
        )

        return data

    except Exception as error:

        print(
            f"[-] Feodo parsing failed: {error}"
        )

        return []


def collect_phishunt():
    """
    Download and parse Phishunt.
    """

    feed_path = RAW_DATA_DIR / "phishunt.csv"

    print()
    print("[FEED] Phishunt")

    print(
        "[+] Downloading Phishunt feed..."
    )

    success = download_phishunt_feed(
        str(feed_path)
    )

    if not success:

        print(
            "[-] Phishunt download failed."
        )

        return []

    try:

        data = parse_phishunt_file(
            str(feed_path)
        )

        print(
            f"[+] Phishunt records: {len(data)}"
        )

        return data

    except Exception as error:

        print(
            f"[-] Phishunt parsing failed: {error}"
        )

        return []


def save_json(data, output_path):
    """
    Save data as JSON.
    """

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )


def run_pipeline():
    """
    Run the complete Threat Intelligence Aggregator.
    """

    print()
    print("=" * 60)
    print(
        "       THREAT INTELLIGENCE AGGREGATOR"
    )
    print("=" * 60)

    # =========================
    # FEED COLLECTION
    # =========================

    feodo_iocs = collect_feodo()

    phishunt_iocs = collect_phishunt()

    all_raw_iocs = (
        feodo_iocs
        + phishunt_iocs
    )

    print()
    print(
        f"[+] Total raw IOCs: "
        f"{len(all_raw_iocs)}"
    )

    # =========================
    # NORMALIZATION
    # =========================

    normalized_iocs = normalize_iocs(
        all_raw_iocs
    )

    print(
        f"[+] Unique IOCs: "
        f"{len(normalized_iocs)}"
    )

    # =========================
    # CORRELATION
    # =========================

    correlated_iocs = correlate_iocs(
        normalized_iocs
    )

    correlated_count = sum(
        1
        for item in correlated_iocs
        if item.get(
            "source_count",
            0
        ) >= 2
    )

    print(
        f"[+] Correlated IOCs: "
        f"{correlated_count}"
    )

    # =========================
    # RISK SCORING
    # =========================

    scored_iocs = apply_risk_scoring(
        correlated_iocs
    )

    high = sum(
        1
        for item in scored_iocs
        if item.get(
            "risk_level"
        ) == "HIGH"
    )

    medium = sum(
        1
        for item in scored_iocs
        if item.get(
            "risk_level"
        ) == "MEDIUM"
    )

    low = sum(
        1
        for item in scored_iocs
        if item.get(
            "risk_level"
        ) == "LOW"
    )

    print()
    print("RISK SUMMARY")
    print("-" * 60)

    print(
        f"HIGH   : {high}"
    )

    print(
        f"MEDIUM : {medium}"
    )

    print(
        f"LOW    : {low}"
    )

    # =========================
    # SAVE RESULTS
    # =========================

    output_path = (
        OUTPUT_DATA_DIR
        / "ti_results.json"
    )

    save_json(
        scored_iocs,
        output_path
    )

    print()
    print(
        f"[+] Results saved to: "
        f"{output_path}"
    )

    # =========================
    # BLOCKLIST GENERATION
    # =========================

    generate_blocklists(
        scored_iocs,
        OUTPUT_DATA_DIR
    )

    # =========================
    # REPORT GENERATION
    # =========================

    report_path = (
        OUTPUT_DATA_DIR
        / "threat_intelligence_report.html"
    )

    generate_threat_report(
        scored_iocs,
        report_path
    )

    print()
    print("=" * 60)

    print(
        "Pipeline completed successfully."
    )

    print("=" * 60)

    return scored_iocs


if __name__ == "__main__":

    run_pipeline()