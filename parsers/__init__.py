"""Parser registry: maps a feed format key to its parse function."""

from pathlib import Path

from parsers.csv_parser import parse_csv_file
from parsers.feodo_parser import parse_feodo_file
from parsers.json_parser import parse_json_file
from parsers.lines import (
    parse_any_lines, parse_cidr_lines, parse_domain_lines, parse_hash_semicolon,
    parse_ip_lines, parse_ipsum, parse_url_lines,
)
from parsers.phishunt_parser import parse_phishunt_file
from parsers.stix_parser import parse_stix_feed
from parsers.threatfox_parser import parse_threatfox_feed
from parsers.txt_parser import parse_txt_file
from parsers.urlhaus_parser import parse_urlhaus_file

# Every registry parser has the signature parser(path, feed) -> [ioc dict].
PARSERS = {
    "feodo_csv": parse_feodo_file,
    "phishunt_csv": parse_phishunt_file,
    "urlhaus_csv": parse_urlhaus_file,
    "threatfox_json": parse_threatfox_feed,
    "stix": parse_stix_feed,
    "ip_lines": parse_ip_lines,
    "ipsum": parse_ipsum,
    "url_lines": parse_url_lines,
    "domain_lines": parse_domain_lines,
    "cidr_lines": parse_cidr_lines,
    "hash_semicolon": parse_hash_semicolon,
    "any_lines": parse_any_lines,
}


def parse_with_feed(feed, path):
    try:
        parser = PARSERS[feed.fmt]
    except KeyError:
        raise ValueError(f"Unknown feed format: {feed.fmt}") from None
    return parser(str(path), feed)


def parse_feed(file_path, source="Unknown"):
    """Parse a local TXT / CSV / JSON (incl. STIX) file by extension."""
    extension = Path(file_path).suffix.lower()
    if extension == ".txt":
        return parse_txt_file(file_path, source)
    if extension == ".csv":
        return parse_csv_file(file_path, source)
    if extension == ".json":
        return parse_json_file(file_path, source)
    raise ValueError(f"Unsupported feed format: {extension}")
