from pathlib import Path

from parsers.txt_parser import parse_txt_file
from parsers.csv_parser import parse_csv_file
from parsers.json_parser import parse_json_file


def parse_feed(file_path, source="Unknown"):
    """
    Automatically select the correct parser based on file extension.
    """

    path = Path(file_path)

    extension = path.suffix.lower()

    if extension == ".txt":
        return parse_txt_file(file_path, source)

    if extension == ".csv":
        return parse_csv_file(file_path, source)

    if extension == ".json":
        return parse_json_file(file_path, source)

    raise ValueError(f"Unsupported feed format: {extension}")