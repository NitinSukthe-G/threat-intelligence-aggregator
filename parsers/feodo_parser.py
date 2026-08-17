import csv

from core.validator import detect_ioc_type


def parse_feodo_file(file_path):
    """
    Parse a Feodo Tracker CSV feed.

    Returns normalized IOC records containing:
    - indicator
    - type
    - source
    - first_seen
    - last_online
    - port
    - status
    - malware
    - category
    - confidence
    """

    results = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore",
        newline=""
    ) as file:

        # Feodo contains comment lines beginning with #.
        lines = (
            line for line in file
            if not line.lstrip().startswith("#")
        )

        reader = csv.DictReader(lines)

        for row in reader:

            ip = row.get("dst_ip", "").strip()

            if not ip:
                continue

            ioc_type = detect_ioc_type(ip)

            if ioc_type != "IP":
                continue

            malware = row.get("malware", "").strip()
            status = row.get("c2_status", "").strip()

            record = {
                "indicator": ip,
                "type": "IP",
                "source": "Feodo Tracker",

                "first_seen": row.get(
                    "first_seen_utc",
                    ""
                ).strip(),

                "last_online": row.get(
                    "last_online",
                    ""
                ).strip(),

                "port": row.get(
                    "dst_port",
                    ""
                ).strip(),

                "status": status,

                "malware": malware,

                "category": "botnet",

                "confidence": 0
            }

            results.append(record)

    return results