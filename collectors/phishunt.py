from collectors.http_downloader import download_file


PHISHUNT_FEED_URL = "https://phishunt.io/feed.csv"


def download_phishunt_feed(output_path):
    """
    Download the current Phishunt CSV feed.
    """

    return download_file(
        PHISHUNT_FEED_URL,
        output_path
    )