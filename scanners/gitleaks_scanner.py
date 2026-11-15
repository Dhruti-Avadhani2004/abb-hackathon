
import json
import shutil
import subprocess
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent

from scan_config import TARGET_DIR
CONFIG_FILE = BASE_DIR / "gitleaks-config" / "gitleaks.toml"
OUTPUT_DIR = BASE_DIR / "scanner_output"

REPORT_FILE = OUTPUT_DIR / "gitleaks_output.json"
LOG_FILE = OUTPUT_DIR / "gitleaks_output.txt"

# Locate Gitleaks
GITLEAKS_PATH = shutil.which("gitleaks")


def main():

    if not TARGET_DIR.is_dir():
        print(f"Target directory not found: {TARGET_DIR}")
        return

    if not CONFIG_FILE.is_file():
        print(f"Gitleaks configuration not found: {CONFIG_FILE}")
        return

    if not GITLEAKS_PATH:
        print("Gitleaks executable not found.")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\nStarting Gitleaks secret scan...")

    # Remove previous report to prevent stale results
    if REPORT_FILE.exists():
        REPORT_FILE.unlink()

    command = [
        GITLEAKS_PATH,
        "dir",
        str(TARGET_DIR),
        "--config",
        str(CONFIG_FILE),
        "--report-format",
        "json",
        "--report-path",
        str(REPORT_FILE),
        "--exit-code",
        "0",
        "--no-banner"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    output = result.stdout + result.stderr

    LOG_FILE.write_text(
        output,
        encoding="utf-8"
    )

    if result.returncode != 0:
        print("Gitleaks scan failed.")
        print(output)
        return

    if not REPORT_FILE.exists():
        print("Gitleaks report was not generated.")
        return

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            findings = json.load(file)

        finding_count = len(findings)

        print("\n===== Gitleaks Scan Summary =====")
        print(f"Findings: {finding_count}")
        print(f"JSON Report: {REPORT_FILE}")
        print(f"Log: {LOG_FILE}")

    except (json.JSONDecodeError, OSError) as error:
        print(f"Could not read Gitleaks report: {error}")


if __name__ == "__main__":
    main()
