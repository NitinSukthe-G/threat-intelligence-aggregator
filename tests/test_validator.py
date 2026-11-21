import pytest

from core.validator import (
    detect_ioc_type, extract_iocs, is_public_ip, is_valid_cidr, is_valid_domain,
    is_valid_hash, is_valid_url, refang,
)


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "IP"), ("2001:db8::1", "IP"),
    ("example.com", "DOMAIN"), ("sub.example.co.uk", "DOMAIN"),
    ("https://example.com/a?b=C", "URL"), ("http://1.2.3.4:8080/x", "URL"),
    ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256"),
    ("user@example.com", "EMAIL"),
    ("hxxps://evil[.]example[.]net/login", "URL"),
    ("evil[.]net", "DOMAIN"),
    ("not valid", "UNKNOWN"), ("", "UNKNOWN"), ("999.1.1.1", "UNKNOWN"),
    ("file.txt", "UNKNOWN"), ("foo.php", "UNKNOWN"), ("localhost", "UNKNOWN"),
    ("ftp://example.com", "UNKNOWN"), ("-bad-.com", "UNKNOWN"),
])
def test_detect_ioc_type(value, expected):
    assert detect_ioc_type(value) == expected


def test_refang_variants():
    assert refang("hxxp://a[.]b[:]80") == "http://a.b:80"
    assert refang("user[at]example(.)com") == "user@example.com"


def test_hash_case_insensitive():
    assert is_valid_hash("D41D8CD98F00B204E9800998ECF8427E") == "MD5"
    assert is_valid_hash("zz" * 16) is False


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("10.0.0.1", False), ("192.168.1.1", False),
    ("127.0.0.1", False), ("192.0.2.5", False), ("169.254.1.1", False),
    ("not-an-ip", False),
])
def test_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_cidr():
    assert is_valid_cidr("1.2.3.0/24")
    assert not is_valid_cidr("1.2.3.4")
    assert not is_valid_cidr("1.2.3.0/99")


def test_url_requires_host():
    assert not is_valid_url("http://")
    assert not is_valid_url("javascript:alert(1)")


def test_domain_length_limits():
    assert not is_valid_domain("a" * 64 + ".com")
    assert is_valid_domain("a" * 63 + ".com")


def test_extract_iocs_free_text():
    text = ("See hxxps://bad[.]example[.]net/x and 8.8.4.4, mail a@b.org "
            "hash d41d8cd98f00b204e9800998ecf8427e twice d41d8cd98f00b204e9800998ecf8427e")
    found = dict(extract_iocs(text))
    assert found["https://bad.example.net/x"] == "URL"
    assert found["8.8.4.4"] == "IP"
    assert found["a@b.org"] == "EMAIL"
    assert found["d41d8cd98f00b204e9800998ecf8427e"] == "MD5"
    assert len(extract_iocs(text)) == 4  # de-duplicated, URL host not double counted
