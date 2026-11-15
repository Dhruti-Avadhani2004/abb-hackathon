from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent

TARGET_DIR = Path(
    os.environ.get("SCAN_TARGET", str(BASE_DIR / "sgc-gatekeeper-testbed"))
).resolve()

OUTPUT_DIR = BASE_DIR / "scanner_output"