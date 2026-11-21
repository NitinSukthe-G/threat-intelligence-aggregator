import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
OUTPUT_DATA_DIR = DATA_DIR / "output"
SAMPLES_DIR = DATA_DIR / "samples"
LOCAL_FEEDS_DIR = DATA_DIR / "local"


def _clean_key(name, *aliases):
    for key in (name, *aliases):
        value = os.getenv(key, "").strip()
        if value and value != "YOUR_AUTH_KEY_HERE":
            return value
    return ""


# One free abuse.ch Auth-Key unlocks URLhaus and ThreatFox.
ABUSECH_AUTH_KEY = _clean_key("ABUSECH_AUTH_KEY", "URLHAUS_AUTH_KEY")

# Token that protects POST /api/run. Empty = pipeline runs are open (local dev).
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
RUN_COOLDOWN_SECONDS = int(os.getenv("RUN_COOLDOWN_SECONDS", "300"))

# Pipeline tuning.
BLOCKLIST_MIN_SCORE = int(os.getenv("BLOCKLIST_MIN_SCORE", "35"))
STORE_LOW_CAP = int(os.getenv("STORE_LOW_CAP", "2000"))
STALE_AFTER_HOURS = int(os.getenv("STALE_AFTER_HOURS", "12"))
INCLUDE_SAMPLES = os.getenv("INCLUDE_SAMPLES", "0") == "1"
EXTRA_ALLOW_DOMAINS = tuple(
    d.strip().lower() for d in os.getenv("ALLOW_DOMAINS", "").split(",") if d.strip()
)
EXTRA_ALLOW_IPS = tuple(
    i.strip() for i in os.getenv("ALLOW_IPS", "").split(",") if i.strip()
)

for directory in (RAW_DATA_DIR, OUTPUT_DATA_DIR, LOCAL_FEEDS_DIR):
    directory.mkdir(parents=True, exist_ok=True)
