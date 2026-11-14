
import subprocess
from pathlib import Path
from datetime import datetime
import json

BASE_DIR = Path(__file__).resolve().parent.parent

TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
OUTPUT_DIR = BASE_DIR / "scanner_output"

ESLINT_CMD = TARGET_DIR / "node_modules" / ".bin" / "eslint.cmd"

JSON_REPORT = OUTPUT_DIR / "eslint_output.json"
TEXT_REPORT = OUTPUT_DIR / "eslint_output.txt"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Starting ESLint security scan...")
    print(f"Target: {TARGET_DIR}")

    if not TARGET_DIR.exists():
        print("Target directory not found.")
        return

    if not ESLINT_CMD.exists():
        print("ESLint executable not found.")
        print("Install ESLint dependencies inside the target directory.")
        return

    start_time = datetime.now()

    common_args = [
        "cmd",
        "/c",
        str(ESLINT_CMD),
        ".",
        "--format",
        "json",
        "--output-file",
        str(JSON_REPORT)
    ]

    try:
        json_result = subprocess.run(
            common_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(TARGET_DIR)
        )

        if json_result.returncode not in (0, 1):
            print("ESLint scan failed.")
            print(json_result.stderr)
            return

        if not JSON_REPORT.exists():
            print("ESLint JSON report was not generated.")
            return

        with open(JSON_REPORT, "r", encoding="utf-8") as report:
            data = json.load(report)

        total_errors = 0
        total_warnings = 0
        total_files = len(data)

        for file_result in data:
            total_errors += file_result.get("errorCount", 0)
            total_warnings += file_result.get("warningCount", 0)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        text_command = [
            "cmd",
            "/c",
            str(ESLINT_CMD),
            "."
        ]

        text_result = subprocess.run(
            text_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(TARGET_DIR)
        )

        with open(TEXT_REPORT, "w", encoding="utf-8") as report:
            report.write(text_result.stdout)
            report.write(text_result.stderr)

        print("\n===== ESLint Scan Summary =====")
        print("Status: SUCCESS")
        print(f"Files scanned: {total_files}")
        print(f"Total errors: {total_errors}")
        print(f"Total warnings: {total_warnings}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"JSON Report: {JSON_REPORT}")
        print(f"Text Report: {TEXT_REPORT}")
        print("================================")

    except Exception as error:
        print(f"ESLint execution error: {error}")


if __name__ == "__main__":
    main()
