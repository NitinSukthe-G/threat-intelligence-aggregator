"""IOC validation, defanging and extraction helpers (pure stdlib)."""

import ipaddress
import re
from urllib.parse import urlsplit

HASH_PATTERNS = (
    (re.compile(r"[a-f0-9]{32}"), "MD5"),
    (re.compile(r"[a-f0-9]{40}"), "SHA1"),
    (re.compile(r"[a-f0-9]{64}"), "SHA256"),
)

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z][A-Za-z0-9\-]{1,62}$"
)
_URL_RE = re.compile(r"^https?://[^\s<>\"']+$", re.IGNORECASE)

# Tokens that look like domains but are really file names / reserved names.
_FAKE_TLDS = {
    "txt", "csv", "json", "py", "js", "html", "htm", "php", "exe", "dll",
    "png", "jpg", "gif", "css", "md", "xml", "zip", "log", "local", "lan",
    "internal", "invalid", "test", "example",
}

IOC_REGEX = re.compile(
    r"(?P<url>https?://[^\s<>\"']+)"
    r"|(?P<email>[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,63})"
    r"|(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<hash>\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b)"
    r"|(?P<domain>\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b)"
)


def refang(value):
    """Undo common defanging: hxxp://, [.], (.), [:], [at]."""
    value = str(value).strip().strip("\"'<>")
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    value = re.sub(r"^fxp", "ftp", value, flags=re.IGNORECASE)
    for old, new in (
        ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"),
        ("[://]", "://"), ("[at]", "@"), ("(at)", "@"), ("[@]", "@"),
    ):
        value = value.replace(old, new)
    return value


def refang_text(text):
    text = re.sub(r"\bhxxp", "http", text, flags=re.IGNORECASE)
    for old, new in (("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[at]", "@")):
        text = text.replace(old, new)
    return text


def is_valid_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_public_ip(value):
    """True only for globally routable addresses."""
    try:
        return ipaddress.ip_address(str(value).strip()).is_global
    except ValueError:
        return False


def is_valid_cidr(value):
    value = str(value).strip()
    if "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hash(value):
    value = str(value).strip().lower()
    for pattern, name in HASH_PATTERNS:
        if pattern.fullmatch(value):
            return name
    return False


def is_valid_email(value):
    return bool(_EMAIL_RE.match(str(value).strip()))


def is_valid_domain(value):
    value = str(value).strip().rstrip(".")
    if not _DOMAIN_RE.match(value):
        return False
    return value.rsplit(".", 1)[-1].lower() not in _FAKE_TLDS


def is_valid_url(value):
    value = str(value).strip()
    if not _URL_RE.match(value):
        return False
    try:
        return bool(urlsplit(value).hostname)
    except ValueError:
        return False


def detect_ioc_type(value):
    """Return IP, URL, DOMAIN, MD5, SHA1, SHA256, EMAIL or UNKNOWN."""
    value = refang(value)
    if not value:
        return "UNKNOWN"
    if is_valid_ip(value):
        return "IP"
    hash_type = is_valid_hash(value)
    if hash_type:
        return hash_type
    if is_valid_url(value):
        return "URL"
    if is_valid_email(value):
        return "EMAIL"
    if is_valid_domain(value):
        return "DOMAIN"
    return "UNKNOWN"


def extract_iocs(text):
    """Pull every IOC out of free text. Returns a list of (value, type)."""
    found, seen = [], set()
    for match in IOC_REGEX.finditer(refang_text(text)):
        value = match.group(match.lastgroup).rstrip(".,;)")
        ioc_type = detect_ioc_type(value)
        if ioc_type == "UNKNOWN" or (value, ioc_type) in seen:
            continue
        seen.add((value, ioc_type))
        found.append((value, ioc_type))
    return found
