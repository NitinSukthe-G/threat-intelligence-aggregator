import csv
import json
from pathlib import Path


def generate_blocklists(iocs, output_dir):
    """
    Generate IOC blocklists in TXT, CSV, and JSON formats.

    Only HIGH and MEDIUM risk IOCs are included.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ip_list = []
    domain_list = []
    url_list = []
    hash_list = []

    selected_iocs = []

    for ioc in iocs:
        risk_level = ioc.get("risk_level", "LOW")

        if risk_level not in {"HIGH", "MEDIUM"}:
            continue

        selected_iocs.append(ioc)

        ioc_type = ioc.get("type", "")
        indicator = ioc.get("indicator", "")

        if ioc_type == "IP":
            ip_list.append(indicator)

        elif ioc_type == "DOMAIN":
            domain_list.append(indicator)

        elif ioc_type == "URL":
            url_list.append(indicator)

        elif ioc_type in {"MD5", "SHA1", "SHA256"}:
            hash_list.append(indicator)

    # Remove duplicates while preserving order.
    ip_list = list(dict.fromkeys(ip_list))
    domain_list = list(dict.fromkeys(domain_list))
    url_list = list(dict.fromkeys(url_list))
    hash_list = list(dict.fromkeys(hash_list))

    _write_txt(output_dir / "ip_blocklist.txt", ip_list)
    _write_txt(output_dir / "domain_blocklist.txt", domain_list)
    _write_txt(output_dir / "url_blocklist.txt", url_list)
    _write_txt(output_dir / "hash_blocklist.txt", hash_list)

    _write_csv(
        output_dir / "blocklist.csv",
        selected_iocs
    )

    _write_json(
        output_dir / "blocklist.json",
        selected_iocs
    )

    print()
    print("[+] Blocklists generated")
    print(f"[+] IPs     : {len(ip_list)}")
    print(f"[+] Domains : {len(domain_list)}")
    print(f"[+] URLs    : {len(url_list)}")
    print(f"[+] Hashes  : {len(hash_list)}")


def _write_txt(path, values):
    with open(path, "w", encoding="utf-8") as file:
        for value in values:
            file.write(f"{value}\n")


def _write_csv(path, records):
    fieldnames = [
        "indicator",
        "type",
        "sources",
        "source_count",
        "risk_score",
        "risk_level",
        "category",
        "malware",
    ]

    with open(
        path,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for record in records:
            writer.writerow(
                {
                    "indicator": record.get("indicator", ""),
                    "type": record.get("type", ""),
                    "sources": ", ".join(
                        record.get("sources", [])
                    ),
                    "source_count": record.get(
                        "source_count", 0
                    ),
                    "risk_score": record.get(
                        "risk_score", 0
                    ),
                    "risk_level": record.get(
                        "risk_level", ""
                    ),
                    "category": record.get(
                        "category", ""
                    ),
                    "malware": record.get(
                        "malware", ""
                    ),
                }
            )


def _write_json(path, records):
    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            records,
            file,
            indent=4
        )