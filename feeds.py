"""Central feed registry - add a feed here and the pipeline picks it up."""

from dataclasses import dataclass, field
from typing import Tuple

import config


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    fmt: str                      # parser key, see parsers/registry.py
    category: str = "malicious"
    confidence: int = 60
    weight: int = 6               # source reputation, 0-15
    max_age_hours: int = 6        # reuse cached download younger than this
    aggregates: Tuple[str, ...] = field(default_factory=tuple)
    requires_key: str = ""        # config attribute holding an API key
    corroborate_only: bool = False  # only confirms IOCs other feeds report
    description: str = ""
    options: Tuple = field(default_factory=tuple)

    @property
    def key_value(self):
        return getattr(config, self.requires_key, "") if self.requires_key else ""

    @property
    def filename(self):
        return "".join(c if c.isalnum() else "_" for c in self.name.lower()) + ".feed"


FEEDS = [
    Feed(
        "Feodo Tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
        "feodo_csv", category="botnet", confidence=90, weight=15,
        description="abuse.ch botnet C2 IP addresses",
    ),
    Feed(
        "Phishunt", "https://phishunt.io/feed.csv", "phishunt_csv",
        category="phishing", confidence=70, weight=9,
        description="Phishing URLs and domains, cross-checked by multiple engines",
    ),
    Feed(
        "OpenPhish", "https://openphish.com/feed.txt", "url_lines",
        category="phishing", confidence=80, weight=10,
        description="OpenPhish community phishing URL feed",
    ),
    Feed(
        "Phishing.Army", "https://phishing.army/download/phishing_army_blocklist.txt",
        "domain_lines", category="phishing", confidence=60, weight=6,
        aggregates=("OpenPhish", "Phishunt"), corroborate_only=True,
        description="Aggregated phishing domains (used to corroborate other feeds)",
    ),
    Feed(
        "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "ip_lines",
        category="malicious", confidence=70, weight=8,
        description="CINS Score list of hostile IP addresses",
    ),
    Feed(
        "Blocklist.de", "https://lists.blocklist.de/lists/all.txt", "ip_lines",
        category="attacker", confidence=60, weight=6,
        description="IPs reported for SSH/mail/web attacks",
    ),
    Feed(
        "ET Compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ip_lines", category="malicious", confidence=75, weight=8,
        description="Emerging Threats known compromised hosts",
    ),
    Feed(
        "IPsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "ipsum", category="malicious", confidence=65, weight=7,
        aggregates=("CINS Army", "Blocklist.de", "ET Compromised"),
        options=(("min_lists", 3),),
        description="IPs that appear on 3+ public blacklists",
    ),
    Feed(
        "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "cidr_lines",
        category="botnet", confidence=90, weight=12, max_age_hours=12,
        description="Netblocks hijacked or leased by criminal operations",
    ),
    Feed(
        "Loki Hash IOCs",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt",
        "hash_semicolon", category="malware", confidence=85, weight=12, max_age_hours=24,
        description="Known-evil file hashes (MD5/SHA1/SHA256)",
    ),
    Feed(
        "URLhaus", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "urlhaus_csv", category="malware", confidence=90, weight=14,
        requires_key="ABUSECH_AUTH_KEY",
        description="abuse.ch malware distribution URLs (needs free Auth-Key)",
    ),
    Feed(
        "ThreatFox", "https://threatfox-api.abuse.ch/api/v1/", "threatfox_json",
        category="malware", confidence=85, weight=14, requires_key="ABUSECH_AUTH_KEY",
        description="abuse.ch IOCs tagged with malware families (needs free Auth-Key)",
    ),
]

FEEDS_BY_NAME = {feed.name: feed for feed in FEEDS}


def source_weights():
    return {feed.name: feed.weight for feed in FEEDS}


def aggregate_map():
    return {feed.name: list(feed.aggregates) for feed in FEEDS if feed.aggregates}


def corroborate_only_names():
    return {feed.name for feed in FEEDS if feed.corroborate_only}
