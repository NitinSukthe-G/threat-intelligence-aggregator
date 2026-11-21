"""Filter out indicators that must never be blocked (false-positive guard)."""

from core.validator import is_public_ip

# Major infrastructure that often appears inside phishing URL paths. Blocking
# the apex domain would cause outages, so these are never emitted.
SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "cloudflare.com", "facebook.com", "wikipedia.org", "youtube.com",
    "office.com", "live.com", "windows.net", "azure.com", "akamai.net",
    "amazonaws.com", "googleusercontent.com", "linkedin.com", "twitter.com",
    "x.com", "dropbox.com", "docker.com", "python.org", "mozilla.org",
}

# Free hosting / site-builder platforms: the apex must never be blocked, but
# individual abusive subdomains (evil.pages.dev) are legitimate indicators.
SHARED_PLATFORMS = {
    "blogspot.com", "pages.dev", "vercel.app", "netlify.app", "weebly.com",
    "wixsite.com", "wix.com", "github.io", "herokuapp.com", "web.app",
    "firebaseapp.com", "workers.dev", "000webhostapp.com", "webflow.io",
    "glitch.me", "repl.co", "godaddysites.com", "square.site", "carrd.co",
    "wordpress.com", "medium.com", "notion.site", "framer.app", "r2.dev",
    "ipfs.io", "sharepoint.com", "forms.gle", "bit.ly", "tinyurl.com",
}

SAFE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}


def is_safe_domain(domain, extra=()):
    domain = domain.lower().rstrip(".")
    return any(
        domain == safe or domain.endswith("." + safe)
        for safe in SAFE_DOMAINS.union(extra)
    )


def allowlist_reason(indicator, ioc_type, extra_domains=(), extra_ips=()):
    """Return a reason string if the IOC must be dropped, else ''."""
    if ioc_type == "IP":
        if indicator in SAFE_IPS or indicator in extra_ips:
            return "allowlisted IP"
        if not is_public_ip(indicator):
            return "non-routable IP"
    elif ioc_type == "DOMAIN":
        if is_safe_domain(indicator, extra_domains):
            return "allowlisted domain"
        if indicator.lower().rstrip(".") in SHARED_PLATFORMS:
            return "shared hosting platform apex"
    return ""


def filter_allowlisted(iocs, extra_domains=(), extra_ips=()):
    """Return (kept, {reason: dropped_count})."""
    kept, dropped = [], {}
    for ioc in iocs:
        reason = allowlist_reason(
            ioc["indicator"], ioc["type"], extra_domains, extra_ips
        )
        if reason:
            dropped[reason] = dropped.get(reason, 0) + 1
        else:
            kept.append(ioc)
    return kept, dropped
