import csv

from core.validator import detect_ioc_type


def parse_urlhaus_file(file_path):
    """
    Parse URLhaus CSV data and convert each malware URL
    into our unified IOC structure.
    """

    results = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore",
        newline=""
    ) as file:

        lines = (
            line
            for line in file
            if not line.lstrip().startswith("#")
        )

        reader = csv.DictReader(lines)

        for row in reader:

            url = row.get("url", "").strip()

            if not url:
                continue

            ioc_type = detect_ioc_type(url)

            if ioc_type != "URL":
                continue

            results.append(
                {
                    "indicator": url,
                    "type": "URL",
                    "source": "URLhaus",

                    "first_seen": row.get(
                        "dateadded",
                        ""
                    ).strip(),

                    "last_online": row.get(
                        "last_online",
                        ""
                    ).strip(),

                    "status": row.get(
                        "url_status",
                        ""
                    ).strip(),

                    "category": "malware",

                    "confidence": 90,
                }
            )

    return results