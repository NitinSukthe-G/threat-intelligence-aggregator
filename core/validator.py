import re
import ipaddress


def is_valid_ip(value):
    """Check whether a value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hash(value):
    """Check whether a value is MD5, SHA1, or SHA256."""

    value = value.strip().lower()

    if re.fullmatch(r"[a-f0-9]{32}", value):
        return "MD5"

    if re.fullmatch(r"[a-f0-9]{40}", value):
        return "SHA1"

    if re.fullmatch(r"[a-f0-9]{64}", value):
        return "SHA256"

    return False


def is_valid_email(value):
    """Check whether a value looks like an email address."""

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.match(pattern, value))


def is_valid_domain(value):
    """Check whether a value looks like a domain name."""

    pattern = r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    return bool(re.match(pattern, value))


def is_valid_url(value):
    """Check whether a value is an HTTP or HTTPS URL."""

    pattern = r"^https?://[^\s]+$"

    return bool(re.match(pattern, value))


def detect_ioc_type(value):
    """
    Detect the type of IOC.

    Returns:
        IP, URL, DOMAIN, MD5, SHA1, SHA256, EMAIL, or UNKNOWN
    """

    value = value.strip()

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