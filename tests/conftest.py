import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def make_feed(name="Test Feed", **kwargs):
    from feeds import Feed
    defaults = dict(url="http://localhost/x", fmt="ip_lines", category="malicious",
                    confidence=70, weight=8)
    defaults.update(kwargs)
    return Feed(name, **defaults)


@pytest.fixture
def feed():
    return make_feed
