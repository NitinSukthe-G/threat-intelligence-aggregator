import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

RAW_DATA_DIR = DATA_DIR / "raw"

NORMALIZED_DATA_DIR = DATA_DIR / "normalized"

OUTPUT_DATA_DIR = DATA_DIR / "output"

SCREENSHOT_DIR = BASE_DIR / "screenshots"

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

if URLHAUS_AUTH_KEY == "YOUR_AUTH_KEY_HERE":
    URLHAUS_AUTH_KEY = ""


for directory in [
    RAW_DATA_DIR,
    NORMALIZED_DATA_DIR,
    OUTPUT_DATA_DIR,
    SCREENSHOT_DIR,
]:
    directory.mkdir(
        parents=True,
        exist_ok=True
    )