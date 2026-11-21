import json

from core.validator import detect_ioc_type
from parsers.stix_parser import looks_like_stix, parse_stix_document


def parse_json_file(file_path, source="Unknown"):
    """
    Parse a JSON file. STIX 2.x bundles are detected automatically; any other
    JSON document is walked recursively and every IOC-like string is kept.
    """
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        data = json.load(handle)

    if looks_like_stix(data):
        return parse_stix_document(data, source)

    results = []

    def walk(value, depth=0):
        if depth > 25:
            return
        if isinstance(value, str):
            value = value.strip()
            if value:
                ioc_type = detect_ioc_type(value)
                if ioc_type != "UNKNOWN":
                    results.append({"indicator": value, "type": ioc_type, "source": source})
        elif isinstance(value, dict):
            for item in value.values():
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(data)
    return results
