import requests


FEODO_FEED_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
)


def download_feodo_feed(output_path):
    """
    Download the Feodo Tracker IP blocklist.

    Returns:
        True if the download succeeds.
        False if an error occurs.
    """

    try:
        response = requests.get(
            FEODO_FEED_URL,
            timeout=30
        )

        response.raise_for_status()

        with open(output_path, "wb") as file:
            file.write(response.content)

        print(f"[+] Feodo feed saved to: {output_path}")
        print(f"[+] HTTP status: {response.status_code}")
        print(f"[+] Downloaded bytes: {len(response.content)}")

        return True

    except requests.RequestException as error:
        print(f"[-] Failed to download Feodo feed: {error}")
        return False