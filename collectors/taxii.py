"""Minimal TAXII 2.1 client - pulls STIX objects from a collection."""

import requests

ACCEPT = "application/taxii+json;version=2.1"


def fetch_taxii_objects(collection_url, user="", password="", max_objects=5000, timeout=45):
    """
    Return a STIX envelope {"objects": [...]} from
    ``<api_root>/collections/<id>/`` following TAXII pagination.
    """
    url = collection_url.rstrip("/") + "/objects/"
    auth = (user, password) if user else None
    headers = {"Accept": ACCEPT, "User-Agent": "Threat-Intelligence-Aggregator/2.0"}
    objects, params = [], {}

    while url and len(objects) < max_objects:
        response = requests.get(url, headers=headers, auth=auth, params=params, timeout=timeout)
        response.raise_for_status()
        envelope = response.json()
        objects.extend(envelope.get("objects", []))
        if envelope.get("more") and envelope.get("next"):
            params = {"next": envelope["next"]}
        else:
            break
    return {"type": "bundle", "objects": objects[:max_objects]}
