from core.validator import extract_iocs


def parse_txt_file(file_path, source="Unknown"):
    """
    Parse a text file. Works for one-IOC-per-line lists *and* free text such
    as pasted reports: every IP, URL, domain, hash and e-mail is extracted,
    defanged indicators (hxxp, [.]) included.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        text = "\n".join(
            line for line in handle if not line.lstrip().startswith("#")
        )
    return [
        {"indicator": value, "type": ioc_type, "source": source}
        for value, ioc_type in extract_iocs(text)
    ]
