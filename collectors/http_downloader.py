import requests


def download_file(url, output_path, timeout=30):
    """
    Download a file from a URL and save it locally.
    """

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": "Threat-Intelligence-Aggregator/1.0"
            }
        )

        response.raise_for_status()

        with open(output_path, "wb") as file:
            file.write(response.content)

        print("[+] Download successful")
        print(f"[+] Source: {url}")
        print(f"[+] Saved to: {output_path}")
        print(f"[+] HTTP status: {response.status_code}")
        print(f"[+] Size: {len(response.content)} bytes")

        return True

    except requests.RequestException as error:
        print(f"[-] Download failed: {error}")
        return False