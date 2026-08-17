from core.validator import detect_ioc_type


def parse_txt_file(file_path, source="Unknown"):
    """
    Parse a TXT file containing one IOC per line.

    Returns a list of dictionaries containing:
    indicator, type, source
    """

    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            indicator = line.strip()

            if not indicator:
                continue

            ioc_type = detect_ioc_type(indicator)

            if ioc_type != "UNKNOWN":
                results.append(
                    {
                        "indicator": indicator,
                        "type": ioc_type,
                        "source": source,
                    }
                )

    return results