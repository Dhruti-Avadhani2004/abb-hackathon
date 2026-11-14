import sys
import subprocess
from pathlib import Path
import json
from datetime import datetime

# Project directories
BASE_DIR = Path(__file__).resolve().parent.parent

TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
OUTPUT_DIR = BASE_DIR / "scanner_output"

JSON_REPORT = OUTPUT_DIR / "bandit_output.json"
TEXT_REPORT = OUTPUT_DIR / "bandit_output.txt"


def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not TARGET_DIR.exists():
        raise FileNotFoundError(
            f"Target directory not found: {TARGET_DIR}"
        )

    start_time = datetime.now()

    print("Starting Bandit Python security scan...")
    print(f"Target: {TARGET_DIR}")

    common_args = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(TARGET_DIR),
        "--severity-level",
        "all",
        "--confidence-level",
        "all",
        "--exit-zero"
    ]

    try:
        # Generate JSON report
        json_command = common_args + [
            "--format", "json",
            "--output", str(JSON_REPORT)
        ]

        json_result = subprocess.run(
            json_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        # Generate text report
        text_command = common_args + [
            "--format", "txt",
            "--output", str(TEXT_REPORT)
        ]

        text_result = subprocess.run(
            text_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if json_result.returncode != 0 or text_result.returncode != 0:
            print("Bandit scan failed.")
            print(json_result.stderr)
            print(text_result.stderr)
            return

        if not JSON_REPORT.exists() or not TEXT_REPORT.exists():
            print("Bandit report generation failed.")
            return

        with open(JSON_REPORT, "r", encoding="utf-8") as report:
            data = json.load(report)

        findings = data.get("results", [])

        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in findings:
            severity = finding.get("issue_severity", "LOW")
            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        print("\n===== Bandit Scan Summary =====")
        print("Status: SUCCESS")
        print(f"Total findings: {len(findings)}")
        print(f"High severity: {severity_counts['HIGH']}")
        print(f"Medium severity: {severity_counts['MEDIUM']}")
        print(f"Low severity: {severity_counts['LOW']}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"JSON Report: {JSON_REPORT}")
        print(f"Text Report: {TEXT_REPORT}")
        print("================================")

    except Exception as error:
        print(f"Bandit execution error: {error}")


if __name__ == "__main__":
    main()
