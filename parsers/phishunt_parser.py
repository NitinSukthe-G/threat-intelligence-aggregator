import csv

from core.validator import detect_ioc_type


def parse_phishunt_file(file_path):
    """
    Parse Phishunt CSV data.

    Extracts URL, domain, and IP indicators
    while preserving useful metadata.
    """

    results = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            return results

        for row in reader:

            url = str(
                row.get("url", "")
            ).strip()

            domain = str(
                row.get("domain", "")
            ).strip()

            ip = str(
                row.get("ip", "")
            ).strip()

            first_seen = str(
                row.get("first_seen", "")
            ).strip()

            last_seen = str(
                row.get("date", "")
            ).strip()

            company = str(
                row.get("company", "")
            ).strip()

            # -------------------------
            # URL IOC
            # -------------------------

            if url:

                ioc_type = detect_ioc_type(url)

                if ioc_type == "URL":

                    results.append(
                        {
                            "indicator": url,
                            "type": "URL",
                            "source": "Phishunt",
                            "first_seen": first_seen,
                            "last_online": last_seen,
                            "category": "phishing",
                            "confidence": 80,
                            "malware": "",
                            "reference": company
                        }
                    )

            # -------------------------
            # DOMAIN IOC
            # -------------------------

            if domain:

                ioc_type = detect_ioc_type(domain)

                if ioc_type == "DOMAIN":

                    results.append(
                        {
                            "indicator": domain,
                            "type": "DOMAIN",
                            "source": "Phishunt",
                            "first_seen": first_seen,
                            "last_online": last_seen,
                            "category": "phishing",
                            "confidence": 80,
                            "malware": "",
                            "reference": company
                        }
                    )

            # -------------------------
            # IP IOC
            # -------------------------

            if ip:

                ioc_type = detect_ioc_type(ip)

                if ioc_type == "IP":

                    results.append(
                        {
                            "indicator": ip,
                            "type": "IP",
                            "source": "Phishunt",
                            "first_seen": first_seen,
                            "last_online": last_seen,
                            "category": "phishing-host",
                            "confidence": 70,
                            "malware": "",
                            "reference": company
                        }
                    )

    return results