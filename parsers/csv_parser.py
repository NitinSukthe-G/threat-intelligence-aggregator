import csv

from core.validator import detect_ioc_type

_IOC_COLUMNS = {"indicator", "ioc", "value", "observable", "url", "ip", "domain",
                "hash", "md5", "sha1", "sha256", "address", "host", "email"}
_META = {
    "category": ("category", "type_desc", "threat_type"),
    "malware": ("malware", "family", "malware_family"),
    "confidence": ("confidence", "score"),
    "first_seen": ("first_seen", "first_seen_utc", "date_added", "dateadded"),
    "reference": ("reference", "description", "comment", "source_url"),
}


def _meta(row):
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k}
    meta = {}
    for field, names in _META.items():
        for name in names:
            value = str(lowered.get(name, "") or "").strip()
            if value:
                if field == "confidence":
                    try:
                        value = max(0, min(100, int(float(value))))
                    except ValueError:
                        continue
                meta[field] = value
                break
    return meta


def parse_csv_file(file_path, source="Unknown"):
    """
    Parse a CSV file. Columns named like IOC fields are preferred; if none
    exist every cell is inspected. Optional metadata columns are carried over.
    """
    results = []
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        lines = (line for line in handle if not line.lstrip().startswith("#"))
        reader = csv.DictReader(lines)
        if not reader.fieldnames:
            return results
        named = [c for c in reader.fieldnames if c and c.strip().lower() in _IOC_COLUMNS]

        for row in reader:
            meta = _meta(row)
            cells = [row.get(c) for c in named] if named else list(row.values())
            for cell in cells:
                if not cell or isinstance(cell, list):
                    continue
                value = str(cell).strip()
                ioc_type = detect_ioc_type(value)
                if ioc_type != "UNKNOWN":
                    results.append({"indicator": value, "type": ioc_type,
                                    "source": source, **meta})
    return results
