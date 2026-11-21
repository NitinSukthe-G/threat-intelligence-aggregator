"""Resilient feed downloader: retries, caching and stale-cache fallback."""

import time
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "Threat-Intelligence-Aggregator/2.0 (+defensive research)"
MAX_BYTES = 60 * 1024 * 1024


@dataclass
class FetchResult:
    status: str            # fresh | cached | stale | skipped | failed
    path: Path = None
    size: int = 0
    error: str = ""
    seconds: float = 0.0

    @property
    def usable(self):
        return self.status in {"fresh", "cached", "stale"} and self.path is not None


def _session():
    session = requests.Session()
    retry = Retry(
        total=3, backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.headers["User-Agent"] = USER_AGENT
    return session


def _age_hours(path):
    return (time.time() - path.stat().st_mtime) / 3600


def fetch_feed(feed, cache_dir, force=False, timeout=45):
    """Download ``feed`` into ``cache_dir`` and return a FetchResult."""
    started = time.time()
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / feed.filename

    if feed.requires_key and not feed.key_value:
        return FetchResult("skipped", error=f"{feed.requires_key} not configured")

    if not force and target.exists() and _age_hours(target) < feed.max_age_hours:
        return FetchResult("cached", target, target.stat().st_size,
                           seconds=time.time() - started)

    url = feed.url.replace("{key}", feed.key_value)
    try:
        with _session() as session:
            if feed.fmt == "threatfox_json":
                response = session.post(
                    url, json={"query": "get_iocs", "days": 1},
                    headers={"Auth-Key": feed.key_value}, timeout=timeout,
                )
            else:
                response = session.get(url, timeout=timeout)
            response.raise_for_status()
            content = response.content
        if len(content) > MAX_BYTES:
            raise ValueError("feed exceeds size limit")
        if not content.strip():
            raise ValueError("empty response")
        tmp = target.with_suffix(".tmp")
        tmp.write_bytes(content)
        tmp.replace(target)
        return FetchResult("fresh", target, len(content), seconds=time.time() - started)
    except (requests.RequestException, ValueError, OSError) as error:
        message = f"{type(error).__name__}: {error}"
        if target.exists():  # degrade gracefully to the last good copy
            return FetchResult("stale", target, target.stat().st_size,
                               error=message, seconds=time.time() - started)
        return FetchResult("failed", error=message, seconds=time.time() - started)
