from config import URLHAUS_AUTH_KEY
from collectors.http_downloader import download_file


def download_urlhaus_feed(output_path):
    """
    Download URLhaus recent dataset when an Auth-Key is available.
    """

    if not URLHAUS_AUTH_KEY:
        print("[-] URLhaus Auth-Key not configured.")
        return False

    url = (
        "https://urlhaus-api.abuse.ch/v2/files/exports/"
        f"{URLHAUS_AUTH_KEY}/recent.csv"
    )

    return download_file(
        url,
        output_path
    )