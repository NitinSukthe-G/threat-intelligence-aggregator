import csv
from core.validator import detect_ioc_type


def parse_csv_file(file_path, source="Unknown"):
    """
    Parse a CSV file.

    The parser looks for a column containing IOC values.
    """

    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            return results

        for row in reader:
            for value in row.values():

                if not value:
                    continue

                value = str(value).strip()

                ioc_type = detect_ioc_type(value)

                if ioc_type != "UNKNOWN":
                    results.append(
                        {
                            "indicator": value,
                            "type": ioc_type,
                            "source": source,
                        }
                    )

    return results