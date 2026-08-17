import json
from core.validator import detect_ioc_type


def parse_json_file(file_path, source="Unknown"):
    """
    Parse a JSON file and recursively search for IOC-like values.
    """

    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        data = json.load(file)

    def process_value(value):

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return

            ioc_type = detect_ioc_type(value)

            if ioc_type != "UNKNOWN":
                results.append(
                    {
                        "indicator": value,
                        "type": ioc_type,
                        "source": source,
                    }
                )

        elif isinstance(value, dict):
            for item in value.values():
                process_value(item)

        elif isinstance(value, list):
            for item in value:
                process_value(item)

    process_value(data)

    return results