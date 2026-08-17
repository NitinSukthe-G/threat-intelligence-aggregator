import json
import os

from flask import (
    Flask,
    render_template,
    request,
    send_from_directory,
)

from config import OUTPUT_DATA_DIR
from pipeline import run_pipeline


app = Flask(__name__)

ITEMS_PER_PAGE = 25


def load_results():
    """
    Load the latest processed IOC results.
    """

    result_file = OUTPUT_DATA_DIR / "ti_results.json"

    if not result_file.exists():
        return []

    try:
        with open(
            result_file,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []


def ensure_results():
    """
    Generate results automatically when the deployed service
    starts without an existing result file.

    This is useful because Render's free filesystem is
    temporary across restarts/spin-downs.
    """

    result_file = OUTPUT_DATA_DIR / "ti_results.json"

    if result_file.exists():
        return

    try:
        print("[+] No existing TI results found.")
        print("[+] Running initial threat intelligence pipeline...")
        run_pipeline()

    except Exception as error:
        print(
            f"[-] Initial pipeline execution failed: {error}"
        )


def calculate_dashboard_stats(results):
    """
    Calculate dashboard statistics.
    """

    total_iocs = len(results)

    high = sum(
        1
        for item in results
        if item.get("risk_level") == "HIGH"
    )

    medium = sum(
        1
        for item in results
        if item.get("risk_level") == "MEDIUM"
    )

    low = sum(
        1
        for item in results
        if item.get("risk_level") == "LOW"
    )

    ip_count = sum(
        1
        for item in results
        if item.get("type") == "IP"
    )

    domain_count = sum(
        1
        for item in results
        if item.get("type") == "DOMAIN"
    )

    url_count = sum(
        1
        for item in results
        if item.get("type") == "URL"
    )

    hash_count = sum(
        1
        for item in results
        if item.get("type") in {
            "MD5",
            "SHA1",
            "SHA256",
        }
    )

    email_count = sum(
        1
        for item in results
        if item.get("type") == "EMAIL"
    )

    feed_names = set()

    for item in results:
        for source in item.get(
            "sources",
            [],
        ):
            feed_names.add(source)

    feed_count = len(feed_names)

    correlated_count = sum(
        1
        for item in results
        if item.get(
            "source_count",
            0,
        ) >= 2
    )

    return {
        "total_iocs": total_iocs,
        "high": high,
        "medium": medium,
        "low": low,
        "ip_count": ip_count,
        "domain_count": domain_count,
        "url_count": url_count,
        "hash_count": hash_count,
        "email_count": email_count,
        "feed_count": feed_count,
        "unique_iocs": total_iocs,
        "correlated_count": correlated_count,
    }


@app.route("/")
def dashboard():
    """
    Main dashboard with search, filtering and pagination.
    """

    ensure_results()

    all_results = load_results()

    stats = calculate_dashboard_stats(
        all_results
    )

    search = request.args.get(
        "search",
        "",
    ).strip().lower()

    ioc_type = request.args.get(
        "type",
        "ALL",
    ).upper()

    risk = request.args.get(
        "risk",
        "ALL",
    ).upper()

    try:
        page = int(
            request.args.get(
                "page",
                1,
            )
        )

    except ValueError:
        page = 1

    if page < 1:
        page = 1

    filtered_results = []

    for item in all_results:

        indicator = str(
            item.get(
                "indicator",
                "",
            )
        ).lower()

        current_type = str(
            item.get(
                "type",
                "",
            )
        ).upper()

        current_risk = str(
            item.get(
                "risk_level",
                "",
            )
        ).upper()

        source_text = " ".join(
            item.get(
                "sources",
                [],
            )
        ).lower()

        malware = str(
            item.get(
                "malware",
                "",
            )
        ).lower()

        if search:

            searchable_text = (
                indicator
                + " "
                + source_text
                + " "
                + malware
            )

            if search not in searchable_text:
                continue

        if (
            ioc_type != "ALL"
            and current_type != ioc_type
        ):
            continue

        if (
            risk != "ALL"
            and current_risk != risk
        ):
            continue

        filtered_results.append(item)

    total_filtered = len(
        filtered_results
    )

    total_pages = max(
        1,
        (
            total_filtered
            + ITEMS_PER_PAGE
            - 1
        )
        // ITEMS_PER_PAGE,
    )

    if page > total_pages:
        page = total_pages

    start_index = (
        page - 1
    ) * ITEMS_PER_PAGE

    end_index = (
        start_index
        + ITEMS_PER_PAGE
    )

    page_results = filtered_results[
        start_index:end_index
    ]

    return render_template(
        "index.html",
        results=page_results,
        **stats,
        search=search,
        selected_type=ioc_type,
        selected_risk=risk,
        page=page,
        total_pages=total_pages,
        total_filtered=total_filtered,
        start_index=(
            start_index + 1
            if total_filtered
            else 0
        ),
        end_index=min(
            end_index,
            total_filtered,
        ),
    )


@app.route("/run-pipeline")
def run_pipeline_route():
    """
    Run the TI pipeline from the dashboard.
    """

    try:
        run_pipeline()

    except Exception as error:
        print(
            f"[-] Pipeline error: {error}"
        )

    return dashboard()


@app.route("/download/<filename>")
def download_file(filename):
    """
    Download approved output files.
    """

    allowed_files = {
        "ip_blocklist.txt",
        "domain_blocklist.txt",
        "url_blocklist.txt",
        "hash_blocklist.txt",
        "blocklist.csv",
        "blocklist.json",
        "ti_results.json",
        "threat_intelligence_report.html",
    }

    if filename not in allowed_files:
        return (
            "File not allowed",
            404,
        )

    file_path = (
        OUTPUT_DATA_DIR
        / filename
    )

    if not file_path.exists():
        return (
            "File not found",
            404,
        )

    return send_from_directory(
        OUTPUT_DATA_DIR,
        filename,
        as_attachment=True,
    )


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000,
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )